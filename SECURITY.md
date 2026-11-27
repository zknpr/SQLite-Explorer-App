# Security Policy

SQLite Explorer opens arbitrary, potentially untrusted SQLite databases and
renders their contents in a webview. The shell is designed so that a
compromised webview cannot become arbitrary file access on the user's machine.

## Supported versions

Only the latest [release](https://github.com/zknpr/SQLite-Explorer-App/releases/latest)
receives security fixes. Fixes land on `main` and ship in the next release.

## Reporting a vulnerability

**Do not report security vulnerabilities through public issues, discussions or
pull requests.**

Report them privately through GitHub's private vulnerability reporting:
[open a draft advisory](https://github.com/zknpr/SQLite-Explorer-App/security/advisories/new)
from this repository's **Security** tab. Include:

- the issue and its impact, including what an attacker must already control;
- steps to reproduce or a proof of concept, ideally with a small synthetic
  database;
- the OS, app revision and selected engine (native or WASM);
- any suggested remediation.

The viewer began as the one in the
[SQLite Explorer extension](https://github.com/zknpr/SQLite-Explorer) and is
developed in this repository now. Report an issue in it here, even if the
extension may share it.

## Disclosure

We follow coordinated disclosure. Allow a reasonable window for a fix before
public disclosure. Reporters are credited in the fix notes on request.

## Scope

In scope:

- the Tauri shell in `src-tauri/`: commands, the path allowlists, file writes,
  capabilities, CSP and navigation handling;
- the viewer, its workers and the native sidecar, from their sources in
  `viewer/` to what `viewer-dist/` ships;
- the build and release scripts in this repository.

Out of scope:

- vulnerabilities in upstream dependencies, which belong with those projects;
- attacks that require a maliciously modified build;
- the known limitations below, unless you show impact beyond them.

## Security design

- The webview reaches the shell only through app commands and two event
  permissions; `src-tauri/capabilities/default.json` is the boundary.
- Database reads and in-place writes are limited to paths the user picked in a
  native dialog or that the OS delivered. Import sources get a separate
  read-only grant.
- Writes are atomic: an exclusive temporary file, `fsync`, then rename.
- The CSP sets `default-src 'none'`, an eval-free `script-src`, and
  `base-uri`, `form-action` and `frame-ancestors` to `'none'`.
- A navigation handler keeps every webview on the app's own origin. On
  Windows, WebView2 sends a cancelled navigation's request anyway, so a request
  filter also refuses every web request to a host other than the app's own
  before it leaves the machine.
- The native engine refuses `ATTACH`/`DETACH`, and the shell re-checks the
  bound file's identity around every native call.
- Updates (`src-tauri/src/updater.rs`) install only a package whose signature
  verifies against the public key built into the app, for the version the
  release's manifest announces, and never a lower version. The private key is
  kept offline by the maintainer, so control of the GitHub repository alone
  cannot ship an update. The page can neither start an update nor change the
  setting: no capability or app command reaches the updater.

## Known limitations

With a local attacker who already controls the database's directory:

- The allowlisted-path read and the save's final rename match the path exactly;
  they do not refuse a symlink swapped in at that path or pin the file by
  device and inode.

With a compromised page (attacker code running in the viewer), which the
design otherwise keeps away from files:

- Cross-window ownership of a WASM-engine database depends on what each page
  reports, so a compromised page can under-report its own open files and let
  another window open one of them.
- It can exhaust the machine's memory through the native engine, by sending
  each database's engine process a request close to the transfer limit, or with
  SQL alone. The shell bounds its own buffering (about 1 GiB per window), not
  the engine processes' memory. No file is read or written this way.

About updates:

- The manifest a check reads (`latest.json`) is not signed. Whoever controls
  the GitHub repository can withhold an update, or announce one that then fails
  its signature check; they cannot install anything the update key did not sign.
  The app requests a package only from the endpoint's origin and the
  repository's releases path, whatever the manifest names. GitHub answers those
  requests, like the manifest's, with a redirect to its download server, which
  the app follows without checking the host.
- A package is read into memory whole before its signature is checked, so
  whoever controls the releases can also serve one large enough to exhaust the
  app's memory during a check.
- The update key cannot be replaced without a manual reinstall. If it leaked,
  installed copies would accept packages signed with it until their users
  installed a release with a new key by hand.
