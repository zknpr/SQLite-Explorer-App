#!/usr/bin/env node
/**
 * Name the Debian package `sqlite-explorer`. Tauri derives the package name
 * from the product name by kebab-casing it ("SQLite Explorer" becomes
 * "sq-lite-explorer") and has no setting for it, so the release workflow
 * rewrites the built package's control file:
 *
 *   dpkg-deb -R <deb> <dir>
 *   node scripts/release/deb-control.mjs <dir>/DEBIAN/control
 *   dpkg-deb --root-owner-group --build <dir> <deb>
 *
 * Releases before 0.4.0 shipped as `sq-lite-explorer`. The renamed package
 * provides, conflicts with and replaces that name, so `apt install` of a new
 * release removes an installed old one and takes over its files.
 */
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

export const TAURI_NAME = 'sq-lite-explorer';
export const PACKAGE_NAME = 'sqlite-explorer';

/** The control file with the package renamed; an Error for anything unexpected. */
export function renameControl(text) {
  const lines = text.replace(/\n+$/, '').split('\n');
  const at = lines.indexOf(`Package: ${TAURI_NAME}`);
  if (at < 0) return new Error(`the control file names no package ${TAURI_NAME}`);
  if (lines.some((line) => /^(Provides|Conflicts|Replaces):/.test(line))) {
    return new Error('the control file already declares Provides, Conflicts or Replaces');
  }
  lines[at] = `Package: ${PACKAGE_NAME}`;
  lines.push(`Provides: ${TAURI_NAME}`, `Conflicts: ${TAURI_NAME}`, `Replaces: ${TAURI_NAME}`);
  return lines.join('\n') + '\n';
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const control = process.argv[2];
  if (!control) {
    console.error('deb-control: usage: deb-control.mjs <DEBIAN/control>');
    process.exit(1);
  }
  const renamed = renameControl(fs.readFileSync(control, 'utf8'));
  if (renamed instanceof Error) {
    console.error(`deb-control: ${renamed.message}`);
    process.exit(1);
  }
  fs.writeFileSync(control, renamed);
  console.log(`deb-control: ${TAURI_NAME} -> ${PACKAGE_NAME}`);
}
