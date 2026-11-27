#!/usr/bin/env node
/**
 * Fail when THIRD_PARTY_NOTICES.txt and third-party/inventory.json no longer
 * describe what a release build ships. Both were generated once, and nothing
 * regenerates them, so a dependency bump would otherwise ship stale notices
 * silently.
 *
 *   node scripts/release/notices.mjs
 *
 * Checks:
 * - the inventory's Cargo components are exactly the packages a release build
 *   resolves (`cargo metadata` with default features, all targets). The test-only
 *   `qa-webdriver` feature is not in a release, so it is not resolved;
 * - the inventory's viewer npm components are exactly the packages the viewer
 *   build bundles (viewer/scripts/build.mjs viewerNpmPackages), at the versions
 *   it builds with;
 * - every inventoried component appears in THIRD_PARTY_NOTICES.txt.
 *
 * On failure, update the inventory and notices by hand for the new graph (see
 * third-party/README.md) rather than editing this check.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { viewerNpmPackages } from '../../viewer/scripts/build.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/** `name version` of every non-workspace package in a release resolve. */
export function releaseCargoPackages(metadata) {
  const byId = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  return new Set(metadata.resolve.nodes
    .map((node) => byId.get(node.id))
    .filter((pkg) => pkg && pkg.source)
    .map((pkg) => `${pkg.name} ${pkg.version}`));
}

export function checkNotices({ releasePackages, inventory, noticesText, viewerPackages }) {
  const problems = [];
  const cargo = new Set(inventory.components.filter((c) => c.ecosystem === 'Cargo').map((c) => c.component));
  for (const pkg of [...releasePackages].sort()) {
    if (!cargo.has(pkg)) problems.push(`release ships ${pkg}, which the inventory and notices omit`);
  }
  for (const pkg of [...cargo].sort()) {
    if (!releasePackages.has(pkg)) problems.push(`inventory lists ${pkg}, which a release no longer ships`);
  }
  const viewer = new Set(inventory.components.filter((c) => c.ecosystem === 'viewer npm').map((c) => c.component));
  for (const pkg of [...viewerPackages].sort()) {
    if (!viewer.has(pkg)) problems.push(`the viewer bundles ${pkg}, which the inventory and notices omit`);
  }
  for (const pkg of [...viewer].sort()) {
    if (!viewerPackages.has(pkg)) problems.push(`inventory lists ${pkg}, which the viewer no longer bundles`);
  }
  for (const { component } of inventory.components) {
    if (!noticesText.includes(component)) problems.push(`THIRD_PARTY_NOTICES.txt has no section for ${component}`);
  }
  return problems;
}

async function main() {
  const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--format-version', '1',
    '--manifest-path', path.join(repoRoot, 'src-tauri', 'Cargo.toml')], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 }));
  const read = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');
  const problems = checkNotices({
    releasePackages: releaseCargoPackages(metadata),
    inventory: JSON.parse(read('third-party/inventory.json')),
    noticesText: read('THIRD_PARTY_NOTICES.txt'),
    viewerPackages: await viewerNpmPackages()
  });
  if (problems.length > 0) {
    for (const problem of problems) console.error(`notices: ${problem}`);
    console.error(`notices: ${problems.length} problem(s); update third-party/inventory.json and THIRD_PARTY_NOTICES.txt (third-party/README.md)`);
    process.exit(1);
  }
  console.log('notices: inventory and notices match the release dependency graph and the viewer build');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
