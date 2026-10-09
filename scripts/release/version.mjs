#!/usr/bin/env node
/**
 * The app version lives in three files that nothing keeps in step:
 * package.json, src-tauri/Cargo.toml and src-tauri/tauri.conf.json (the one
 * the installers and About dialog report). A release must agree on all three,
 * and a tag build must match them too.
 *
 *   node scripts/release/version.mjs            print the version, fail on drift
 *   node scripts/release/version.mjs --tag vX   also require the tag to match
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export function readVersions(root = repoRoot) {
  const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
  const cargo = read('src-tauri/Cargo.toml').match(/^\[package\][^[]*?^version\s*=\s*"([^"]+)"/m);
  return {
    'package.json': JSON.parse(read('package.json')).version,
    'src-tauri/Cargo.toml': cargo ? cargo[1] : undefined,
    'src-tauri/tauri.conf.json': JSON.parse(read('src-tauri/tauri.conf.json')).version
  };
}

/** The single agreed version, or an Error naming every disagreement. */
export function resolveVersion(versions, tag) {
  const values = Object.entries(versions);
  const missing = values.filter(([, value]) => typeof value !== 'string' || value === '');
  if (missing.length > 0) {
    return new Error(`no version in ${missing.map(([file]) => file).join(', ')}`);
  }
  const distinct = new Set(values.map(([, value]) => value));
  if (distinct.size !== 1) {
    return new Error(`versions disagree: ${values.map(([file, value]) => `${file}=${value}`).join(', ')}`);
  }
  const [version] = distinct;
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    return new Error(`version ${version} is not semver`);
  }
  if (tag !== undefined && tag !== `v${version}`) {
    return new Error(`tag ${tag} does not match version ${version} (expected v${version})`);
  }
  return version;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const tagIndex = argv.indexOf('--tag');
  const tag = tagIndex >= 0 ? argv[tagIndex + 1] : undefined;
  if (tagIndex >= 0 && !tag) {
    console.error('version: --tag needs a value');
    process.exit(1);
  }
  const result = resolveVersion(readVersions(), tag);
  if (result instanceof Error) {
    console.error(`version: ${result.message}`);
    process.exit(1);
  }
  console.log(result);
}
