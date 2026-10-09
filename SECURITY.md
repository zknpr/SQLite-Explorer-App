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

The viewer, workers and native engine are shared with the
[SQLite Explorer extension](https://github.com/zknpr/SQLite-Explorer). Report
an issue in that shared code in either repository; fixes are coordinated
across both.

## Disclosure

We follow coordinated disclosure. Allow a reasonable window for a fix before
public disclosure. Reporters are credited in the fix notes on request.

## Scope

In scope:

- the Tauri shell in `src-tauri/`: commands, the path allowlists, file writes,
  capabilities, CSP and navigation handling;
- the bundled viewer, workers and native sidecar as shipped in `viewer-dist/`;
- the build and sync scripts in this repository.

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

## Known limitations

These assume a local attacker who already controls the database's directory:

- The allowlisted-path read and the save's final rename match the path exactly;
  they do not refuse a symlink swapped in at that path or pin the file by
  device and inode.
- Cross-window ownership of a WASM-engine database depends on what each page
  reports, so a compromised page can under-report its own open files.
