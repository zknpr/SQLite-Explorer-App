import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../src-tauri/bridge.js', import.meta.url), 'utf8');

function bridge(platform = 'Win32', failure) {
  const handlers = new Map(), calls = [], errors = [];
  const window = {
    __TAURI__: { core: { invoke: async (command, args) => {
      calls.push({ command, ...args });
      if (failure) throw failure;
    } } },
    addEventListener: (name, handler) => handlers.set(name, handler)
  };
  runInNewContext(source, { window, navigator: { platform }, console: { error: (...args) => errors.push(args) } });
  const press = (overrides = {}) => {
    const event = {
      key: '+', ctrlKey: true, metaKey: false, altKey: false, shiftKey: false,
      defaultPrevented: false, isComposing: false,
      preventDefault() { this.defaultPrevented = true; },
      stopImmediatePropagation() { this.stopped = true; },
      ...overrides
    };
    handlers.get('keydown')?.(event);
    return event;
  };
  return { calls, errors, press };
}

test('Windows and Linux zoom follow layout-resolved characters, including editor focus', () => {
  for (const platform of ['Win32', 'Linux x86_64']) {
    const b = bridge(platform);
    for (const key of ['+', '=', '-', '0']) {
      const e = b.press({ key, target: { tagName: 'TEXTAREA' } });
      assert.equal(e.defaultPrevented, true);
      assert.equal(e.stopped, true);
    }
    assert.deepEqual(b.calls, [1, 1, -1, 0].map(direction => ({ command: 'adjust_zoom', direction })));
  }
});

test('US shifted plus and Italian unshifted plus each request one zoom step', () => {
  const b = bridge();
  b.press({ key: '+', code: 'Equal', shiftKey: true });
  b.press({ key: '+', code: 'BracketRight', shiftKey: false });
  assert.deepEqual(b.calls.map(x => x.direction), [1, 1]);
});

test('typing, AltGr, composition and existing SQL shortcuts are not intercepted', () => {
  const b = bridge();
  for (const event of [
    { ctrlKey: false }, { altKey: true }, { metaKey: true },
    { isComposing: true }, { defaultPrevented: true },
    { key: 'k', shiftKey: true }, { key: 's' }
  ]) assert.equal(b.press(event).stopped, undefined);
  assert.equal(b.calls.length, 0);
});

test('macOS retains its native shortcut handler', () => {
  const b = bridge('MacIntel');
  b.press({ ctrlKey: false, metaKey: true });
  b.press();
  assert.equal(b.calls.length, 0);
});

test('zoom command failures are reported', async () => {
  const failure = new Error('zoom unavailable');
  const b = bridge('Win32', failure);
  b.press();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(b.errors.length, 1);
  assert.equal(b.errors[0][1], failure);
});

test('viewer readiness waits for native event subscriptions to finish', async () => {
  const pending = [], calls = [];
  const window = {
    __TAURI__: {
      core: { invoke: async command => calls.push(command) },
      webviewWindow: { getCurrentWebviewWindow: () => ({
        listen: name => new Promise(resolve => pending.push({ name, resolve }))
      }) }
    },
    addEventListener() {}
  };
  runInNewContext(source, { window, navigator: { platform: 'Win32' }, console });
  window.__SQLITE_DESKTOP__.onOpenFile(() => {});
  window.__SQLITE_DESKTOP__.onDragDropPaths(() => {});
  const ready = window.__SQLITE_DESKTOP__.viewerReady();
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, [], 'queued startup paths must not be flushed yet');
  pending[0].resolve(() => {});
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, [], 'the drop subscription is still pending');
  pending[1].resolve(() => {});
  await ready;
  assert.deepEqual(calls, ['viewer_ready']);
});

test('a failed native subscription refuses readiness and reports the failure', async () => {
  const failure = new Error('listener registration failed'), calls = [];
  const window = {
    __TAURI__: {
      core: { invoke: async command => calls.push(command) },
      webviewWindow: { getCurrentWebviewWindow: () => ({ listen: async () => { throw failure; } }) }
    },
    addEventListener() {}
  };
  runInNewContext(source, { window, navigator: { platform: 'Win32' }, console });
  window.__SQLITE_DESKTOP__.onOpenFile(() => {});
  await assert.rejects(window.__SQLITE_DESKTOP__.viewerReady(), error => error === failure);
  assert.deepEqual(calls, []);
});
