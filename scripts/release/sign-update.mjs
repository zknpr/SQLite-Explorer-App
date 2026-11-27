#!/usr/bin/env node
/**
 * Signs a draft release's update packages with the offline update key, then
 * uploads the signatures and latest.json, the manifest installed copies read
 * (src-tauri/src/updater.rs). Run by the maintainer on their own machine, from
 * the release's checkout, after the release workflow has drafted the release and
 * before publishing it:
 *
 *   node scripts/release/sign-update.mjs v0.4.1 [--key <file>]
 *
 * The key never leaves that machine: CI builds unsigned packages, so control of
 * the GitHub repository alone cannot ship an update to installed copies.
 * - The key: ~/.tauri/sqlite-explorer-updater.key, or --key. Its .pub must be
 *   the public key in src-tauri/tauri.conf.json.
 * - Its password: TAURI_SIGNING_PRIVATE_KEY_PASSWORD, or on macOS the Keychain
 *   item (service sqlite-explorer-updater, account release). It reaches the
 *   signer through its environment, never a command line, and is never printed.
 *
 * Refuses a release that is not a draft, a package that does not match the
 * draft's SHA256SUMS, and a signature its own check (verifyMinisign) does not
 * accept for the version being released. Publishing the draft stays manual.
 */
import { createHash, createPublicKey, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { REPOSITORY, UPDATER_PACKAGES } from './assemble.mjs';
import { readVersions, resolveVersion } from './version.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const KEYCHAIN = { service: 'sqlite-explorer-updater', account: 'release' };
const DEFAULT_KEY = path.join(os.homedir(), '.tauri', 'sqlite-explorer-updater.key');
// DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows.
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');

/** The text a Tauri key or signature string encodes (base64 of a minisign file). */
function minisignLines(encoded, what) {
  const lines = Buffer.from(encoded.trim(), 'base64').toString('utf8').split('\n').filter((line) => line !== '');
  if (!lines[0]?.startsWith('untrusted comment:')) throw new Error(`${what} is not a minisign file`);
  return lines;
}

/** The algorithm, key id and Ed25519 key of a Tauri public key string. */
export function parsePublicKey(encoded) {
  const raw = Buffer.from(minisignLines(encoded, 'the public key')[1] ?? '', 'base64');
  if (raw.length !== 42 || raw.subarray(0, 2).toString('latin1') !== 'Ed') {
    throw new Error('the public key is not a minisign Ed25519 key');
  }
  return { keyId: raw.subarray(2, 10).toString('hex'), key: raw.subarray(10) };
}

/**
 * Verifies a Tauri update signature as the updater does: the signature over the
 * package (BLAKE2b-512 prehashed for "ED"), the global signature over the
 * trusted comment, and the version the trusted comment binds (the app requires
 * it, requireSignedVersion). Throws on any mismatch; returns the trusted comment.
 */
export function verifyMinisign({ publicKey, signature, data, version }) {
  const pub = parsePublicKey(publicKey);
  const lines = minisignLines(signature, 'the signature');
  const sig = Buffer.from(lines[1] ?? '', 'base64');
  const trusted = lines[2]?.startsWith('trusted comment: ') ? lines[2].slice('trusted comment: '.length) : null;
  const global = Buffer.from(lines[3] ?? '', 'base64');
  if (sig.length !== 74 || trusted === null || global.length !== 64) throw new Error('the signature is malformed');
  const algorithm = sig.subarray(0, 2).toString('latin1');
  if (algorithm !== 'ED' && algorithm !== 'Ed') throw new Error(`unknown signature algorithm ${algorithm}`);
  if (sig.subarray(2, 10).toString('hex') !== pub.keyId) throw new Error('the signature was made with a different key');
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, pub.key]), format: 'der', type: 'spki' });
  const message = algorithm === 'ED' ? createHash('blake2b512').update(data).digest() : data;
  if (!verify(null, message, key, sig.subarray(10))) throw new Error('the signature does not match the package');
  if (!verify(null, Buffer.concat([sig.subarray(10), Buffer.from(trusted, 'utf8')]), key, global)) {
    throw new Error('the trusted comment is not covered by the signature');
  }
  const signed = trusted.split('\t').find((field) => field.startsWith('version:'))?.slice('version:'.length);
  if (signed === undefined) throw new Error('the signature binds no version');
  if (signed.replace(/^v/, '') !== version.replace(/^v/, '')) {
    throw new Error(`the signature is for version ${signed}, not ${version}`);
  }
  return trusted;
}

/** latest.json: one entry per updater target, each the asset's URL and its signature. */
export function updateManifest({ version, tag, pubDate, signatures }) {
  const platforms = {};
  for (const [target, asset] of Object.entries(UPDATER_PACKAGES)) {
    const signature = signatures[target];
    if (typeof signature !== 'string' || signature === '') throw new Error(`no signature for ${target}`);
    platforms[target] = {
      url: `https://github.com/${REPOSITORY}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(asset(version))}`,
      signature
    };
  }
  return {
    version,
    notes: `See https://github.com/${REPOSITORY}/releases/tag/${tag}`,
    pub_date: pubDate,
    platforms
  };
}

/** sha256 hex of every file a sha256sum-format text lists, by name. */
export function parseChecksums(text) {
  const sums = new Map();
  for (const line of text.split('\n')) {
    const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
    if (match) sums.set(match[2], match[1]);
  }
  return sums;
}

/**
 * The Tauri CLI as node and its JavaScript entry point. The .cmd shim npm installs
 * on Windows needs a shell, which execFileSync does not start.
 */
export function signerCommand(root = repoRoot) {
  return [process.execPath, path.join(root, 'node_modules', '@tauri-apps', 'cli', 'tauri.js')];
}

function gh(args, options = {}) {
  return execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...options });
}

function keyPassword() {
  if (process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD) return process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD;
  if (process.platform !== 'darwin') {
    throw new Error('set TAURI_SIGNING_PRIVATE_KEY_PASSWORD (the Keychain is read only on macOS)');
  }
  try {
    return execFileSync('security', ['find-generic-password', '-s', KEYCHAIN.service, '-a', KEYCHAIN.account, '-w'], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']
    }).replace(/\n$/, '');
  } catch {
    throw new Error(`no Keychain item ${KEYCHAIN.service}/${KEYCHAIN.account}: add it with security add-generic-password -s ${KEYCHAIN.service} -a ${KEYCHAIN.account} -w`);
  }
}

function main(argv) {
  const tag = argv[0];
  if (!tag || !/^v\d/.test(tag)) throw new Error('usage: sign-update.mjs <vX.Y.Z> [--key <file>]');
  const keyAt = argv.indexOf('--key');
  const keyPath = path.resolve(keyAt >= 0 ? argv[keyAt + 1] ?? '' : DEFAULT_KEY);
  const version = resolveVersion(readVersions(), tag);
  if (version instanceof Error) throw version;

  const conf = JSON.parse(fs.readFileSync(path.join(repoRoot, 'src-tauri', 'tauri.conf.json'), 'utf8'));
  const trusted = conf.plugins?.updater?.pubkey;
  if (typeof trusted !== 'string') throw new Error('tauri.conf.json has no updater public key');
  const ownPublic = fs.readFileSync(`${keyPath}.pub`, 'utf8').trim();
  if (ownPublic !== trusted.trim()) {
    throw new Error(`${keyPath} is not the update key the app trusts (its .pub differs from tauri.conf.json)`);
  }

  const release = JSON.parse(gh(['release', 'view', tag, '--repo', REPOSITORY, '--json', 'isDraft,assets']));
  if (!release.isDraft) throw new Error(`${tag} is not a draft: sign before publishing`);

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sqlite-explorer-sign-'));
  try {
    const assets = Object.values(UPDATER_PACKAGES).map((asset) => asset(version));
    gh(['release', 'download', tag, '--repo', REPOSITORY, '--dir', work, '--pattern', 'SHA256SUMS',
      ...assets.flatMap((asset) => ['--pattern', asset])]);
    const sums = parseChecksums(fs.readFileSync(path.join(work, 'SHA256SUMS'), 'utf8'));
    for (const asset of assets) {
      const actual = createHash('sha256').update(fs.readFileSync(path.join(work, asset))).digest('hex');
      if (sums.get(asset) !== actual) throw new Error(`${asset} does not match the draft's SHA256SUMS`);
    }

    /** @type {NodeJS.ProcessEnv} */
    const env = { ...process.env, TAURI_SIGNING_PRIVATE_KEY_PASSWORD: keyPassword() };
    delete env.TAURI_SIGNING_PRIVATE_KEY;
    delete env.TAURI_SIGNING_PRIVATE_KEY_PATH;
    const [node, cli] = signerCommand();
    const signatures = {};
    for (const [target, asset] of Object.entries(UPDATER_PACKAGES)) {
      const file = path.join(work, asset(version));
      execFileSync(node, [cli, 'signer', 'sign', '--private-key-path', keyPath, '--app-version', version, file], {
        env, stdio: ['ignore', 'ignore', 'inherit']
      });
      signatures[target] = fs.readFileSync(`${file}.sig`, 'utf8').trim();
      verifyMinisign({ publicKey: trusted, signature: signatures[target], data: fs.readFileSync(file), version });
      console.log(`sign-update: signed and verified ${asset(version)}`);
    }

    const manifest = path.join(work, 'latest.json');
    const text = JSON.stringify(updateManifest({ version, tag, pubDate: new Date().toISOString(), signatures }), null, 2) + '\n';
    fs.writeFileSync(manifest, text);
    gh(['release', 'upload', tag, '--repo', REPOSITORY, '--clobber', manifest,
      ...assets.map((asset) => path.join(work, `${asset}.sig`))]);
    const check = path.join(work, 'check');
    fs.mkdirSync(check);
    gh(['release', 'download', tag, '--repo', REPOSITORY, '--dir', check, '--pattern', 'latest.json']);
    if (fs.readFileSync(path.join(check, 'latest.json'), 'utf8') !== text) {
      throw new Error('the uploaded latest.json differs from the one written');
    }
    console.log(`sign-update: latest.json and ${assets.length} signatures are on the ${tag} draft; publish it when ready`);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`sign-update: ${error.message}`);
    process.exit(1);
  }
}
