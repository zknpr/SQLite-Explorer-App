#!/usr/bin/env node
/**
 * Release asset names and the release job's bookkeeping, in one place so the
 * build jobs and the release job cannot drift apart.
 *
 *   node scripts/release/assemble.mjs asset-name <macos|linux|windows>
 *   node scripts/release/assemble.mjs assemble --dist <dir> --tag <vX.Y.Z>
 *       --commit <sha> --run-url <url> --notes <file>
 *
 * `assemble` refuses a dist directory that is missing a platform or holds
 * anything unexpected, so a partial or polluted release is never drafted. It
 * writes release-manifest.json and SHA256SUMS into the dist directory and the
 * draft release notes to --notes.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { readVersions, resolveVersion } from './version.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const REPOSITORY = 'zknpr/SQLite-Explorer-App';
export const VIEWER_REPOSITORY = 'zknpr/SQLite-Explorer';

export const PLATFORMS = {
  macos: { asset: (v) => `SQLite-Explorer-${v}-macos-aarch64.dmg`, label: 'macOS, Apple Silicon' },
  linux: { asset: (v) => `SQLite-Explorer-${v}-linux-amd64.deb`, label: 'Linux x86-64 (.deb)' },
  windows: { asset: (v) => `SQLite-Explorer-${v}-windows-x64-setup.exe`, label: 'Windows x86-64' }
};
export const SHARED_ASSETS = ['THIRD_PARTY_NOTICES.txt', 'mpl-dependency-sources.tar.gz'];
const GENERATED = ['release-manifest.json', 'SHA256SUMS'];

export function expectedAssets(version) {
  return [...Object.values(PLATFORMS).map((p) => p.asset(version)), ...SHARED_ASSETS].sort();
}

/** Missing and unexpected files, or null when the directory is exactly the release. */
export function checkDist(names, version) {
  const present = names.filter((name) => !GENERATED.includes(name)).sort();
  const expected = expectedAssets(version);
  const missing = expected.filter((name) => !present.includes(name));
  const unexpected = present.filter((name) => !expected.includes(name));
  return missing.length || unexpected.length ? { missing, unexpected } : null;
}

export function sha256File(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

export function buildManifest({ version, tag, commit, runUrl, viewerRef, assets }) {
  return {
    product: 'SQLite Explorer',
    version,
    tag,
    // A semver prerelease (0.3.0-beta.1) must never be published as Latest.
    prerelease: version.includes('-'),
    repository: REPOSITORY,
    commit,
    buildRun: runUrl,
    viewerSource: { repository: VIEWER_REPOSITORY, ref: viewerRef },
    signing: {
      macos: 'the app has an ad-hoc signature with the hardened runtime; the disk image is unsigned; not Developer ID signed or notarized',
      windows: 'unsigned',
      linux: 'unsigned package; verify SHA256SUMS and the build attestation'
    },
    assets
  };
}

/** `sha256sum -c` format, sorted by name. */
export function checksumsText(entries) {
  return [...entries].sort((a, b) => a.name.localeCompare(b.name))
    .map(({ name, sha256 }) => `${sha256}  ${name}`).join('\n') + '\n';
}

/**
 * The PowerShell check the notes publish for Windows, which has no sha256sum.
 * Exported so the Windows build job runs this exact string against its own
 * installer: the documented command is the tested one. Get-FileHash defaults to
 * SHA256 and -eq compares strings case-insensitively, so its upper-case hex
 * matches the lower-case SHA256SUMS line.
 */
export function windowsChecksumCommand(asset) {
  return `(Get-FileHash .\\${asset}).Hash -eq ((Select-String -Path SHA256SUMS -SimpleMatch '${asset}').Line -split ' ')[0]`;
}

export function releaseNotes({ version, commit, runUrl, viewerRef }) {
  const rows = Object.values(PLATFORMS).map((p) => `| ${p.label} | \`${p.asset(version)}\` |`);
  return `SQLite Explorer ${version}: a desktop SQLite browser and editor built on the SQLite Explorer viewer.

Built by [this workflow run](${runUrl}) from ${REPOSITORY}@${commit}, with the viewer from ${VIEWER_REPOSITORY}@${viewerRef}.

| Platform | Download |
| --- | --- |
${rows.join('\n')}

## Before you install

- **macOS:** the app has an ad-hoc signature and is not notarized. The first launch is blocked; open **System Settings → Privacy & Security** and choose **Open Anyway** for SQLite Explorer.
- **Windows:** the installer is unsigned. SmartScreen shows "Windows protected your PC"; choose **More info → Run anyway**. If **Smart App Control** is on, Windows blocks unsigned programs and offers no override, so this release cannot be installed there.
- **Linux:** the package needs glibc 2.39 or newer (Ubuntu 24.04+, Debian 13+). Install it with \`sudo apt install ./${PLATFORMS.linux.asset(version)}\`.

See the [installation notes](https://github.com/${REPOSITORY}#install) for uninstalling and for the platforms this release was tested on.

## Verify the download

Download \`SHA256SUMS\` next to the package, then check it:

- **macOS:** \`shasum -a 256 --check --ignore-missing SHA256SUMS\`
- **Linux:** \`sha256sum --check --ignore-missing SHA256SUMS\`
- **Windows (PowerShell):** \`${windowsChecksumCommand(PLATFORMS.windows.asset(version))}\` prints \`True\` when the file matches.

With the GitHub CLI on any platform, \`gh attestation verify <file> --repo ${REPOSITORY}\` confirms the file was built by this repository's release workflow.

## Licenses

SQLite Explorer is MIT-licensed. Each package carries \`THIRD_PARTY_NOTICES.txt\`, which is also attached here. \`mpl-dependency-sources.tar.gz\` holds the unmodified sources of the MPL-2.0 dependencies. Signing status is described in the [code signing policy](https://github.com/${REPOSITORY}/blob/${commit}/docs/code-signing-policy.md).
`;
}

function arg(argv, flag) {
  const i = argv.indexOf(flag);
  if (i < 0 || !argv[i + 1]) throw new Error(`missing ${flag}`);
  return argv[i + 1];
}

function main(argv) {
  const [command, ...rest] = argv;
  if (command === 'windows-checksum-command') {
    const version = resolveVersion(readVersions());
    if (version instanceof Error) throw version;
    console.log(windowsChecksumCommand(PLATFORMS.windows.asset(version)));
    return;
  }
  if (command === 'asset-name') {
    const platform = PLATFORMS[rest[0]];
    if (!platform) throw new Error(`asset-name needs one of ${Object.keys(PLATFORMS).join(', ')}`);
    const version = resolveVersion(readVersions());
    if (version instanceof Error) throw version;
    console.log(platform.asset(version));
    return;
  }
  if (command !== 'assemble') throw new Error('usage: assemble.mjs asset-name <platform> | assemble --dist ... --tag ... --commit ... --run-url ... --notes ...');
  const dist = path.resolve(arg(rest, '--dist'));
  const tag = arg(rest, '--tag');
  const commit = arg(rest, '--commit');
  const runUrl = arg(rest, '--run-url');
  const notesPath = path.resolve(arg(rest, '--notes'));
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error(`commit ${commit} is not a full SHA`);
  const version = resolveVersion(readVersions(), tag);
  if (version instanceof Error) throw version;
  const problems = checkDist(fs.readdirSync(dist), version);
  if (problems) {
    throw new Error(`dist is not the release: missing [${problems.missing.join(', ')}], unexpected [${problems.unexpected.join(', ')}]`);
  }
  const viewerRef = JSON.parse(fs.readFileSync(path.join(repoRoot, 'viewer-dist', 'manifest.json'), 'utf8')).ref;
  const assets = expectedAssets(version).map((name) => {
    const file = path.join(dist, name);
    return { name, bytes: fs.statSync(file).size, sha256: sha256File(file) };
  });
  const manifestPath = path.join(dist, 'release-manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(buildManifest({ version, tag, commit, runUrl, viewerRef, assets }), null, 2) + '\n');
  const sums = [...assets, { name: 'release-manifest.json', sha256: sha256File(manifestPath) }];
  fs.writeFileSync(path.join(dist, 'SHA256SUMS'), checksumsText(sums));
  fs.writeFileSync(notesPath, releaseNotes({ version, commit, runUrl, viewerRef }));
  for (const { name, sha256 } of sums) console.log(`assemble: ${sha256}  ${name}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`assemble: ${error.message}`);
    process.exit(1);
  }
}
