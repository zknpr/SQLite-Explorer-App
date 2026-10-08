#!/usr/bin/env node
// Read-only diagnostics from the real WKWebView after a Computer Use/manual run.
// This does not replace the OS interaction checklist or mock the desktop bridge.
import assert from 'node:assert/strict';

const [portText, expectedEngine = 'native'] = process.argv.slice(2);
const port = Number(portText);
assert.ok(Number.isInteger(port) && port > 0 && port <= 65535,
    'Usage: node scripts/qa/macos-probe.mjs PORT [native|wasm]');
assert.ok(['native', 'wasm'].includes(expectedEngine), 'Expected engine must be native or wasm');
const base = `http://127.0.0.1:${port}`;
async function request(method, route, body) {
    const response = await fetch(base + route, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(10_000)
    });
    const result = await response.json();
    if (!response.ok || result.value?.error) throw new Error(JSON.stringify(result));
    return result.value;
}

const { sessionId, capabilities } = await request('POST', '/session', {
    capabilities: { alwaysMatch: { browserName: 'webkit' } }
});
assert.ok(sessionId, 'WebDriver did not create a session');
try {
    const snapshot = await request('POST', `/session/${sessionId}/execute/sync`, {
        script: `return (${(() => ({
            url: location.href,
            title: document.title,
            engine: document.querySelector('#engineBadge')?.dataset.engine,
            extensionQueryAction: getComputedStyle(document.querySelector('#btnOpenQuery')).display,
            desktopConsoleButton: !document.querySelector('#btnSqlConsole')?.hidden,
            observations: window.__SQLITE_QA_OBSERVATIONS__,
            status: document.querySelector('#statusText')?.textContent
        })).toString()})();`,
        args: []
    });
    console.log(JSON.stringify({ capabilities, ...snapshot }, null, 2));
    assert.equal(snapshot.url, 'tauri://localhost/viewer.html');
    assert.equal(snapshot.engine, expectedEngine);
    assert.equal(snapshot.extensionQueryAction, 'none');
    assert.equal(snapshot.desktopConsoleButton, true);
    assert.ok(snapshot.observations, 'Build lacks the opt-in startup observer');
    for (const category of ['errors', 'rejections', 'consoleErrors', 'csp']) {
        assert.deepEqual(snapshot.observations[category], [], category);
    }
} finally {
    await request('DELETE', `/session/${sessionId}`);
}
