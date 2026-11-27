# Contributing to SQLite Explorer

Everything the app is built from lives in this repository:

| Change | Source |
| --- | --- |
| Native menus, dialogs, file access, lifecycle and IPC | `src-tauri/` |
| Viewer, grid, SQL console, workers and database behavior | `viewer/` (`core/ui`, `core/native`, `src/core`, the worker) |
| The built viewer and native runtime the shell bundles | `viewer-dist/`, written by `npm run build:viewer` |

The viewer began as the one in the
[SQLite Explorer VS Code extension](https://github.com/zknpr/SQLite-Explorer)
(its v1.9.0) and is developed here now; the two diverge from that point.

Start with the build prerequisites and platform notes in [README.md](README.md).

## Changing the shell

Use the checked-in npm and Cargo lockfiles:

```sh
npm ci
npm run check:viewer
npm test
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
```

For changes to native database operations, run the additional live-sidecar and
runtime checks against the native engine:

```sh
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- --ignored
```

## Changing the viewer or worker

Edit the sources in `viewer/`, then rebuild and check:

```sh
npm run build:viewer
npm run typecheck:viewer
npm test
npm run native-lane
```

`npm run build:viewer` refuses a build whose native worker exposes a method the
shell has not audited, or moves values in pieces on methods the shell does not
expect (`KNOWN_METHODS`, `TRANSPORT_METHODS` and `REQUEST_TRANSFER_METHODS` in
`src-tauri/src/native.rs`). Commit the rebuilt `viewer-dist/` with the source
change: CI runs `npm run check:viewer`, which fails when the committed files are
not what `viewer/` builds. Never edit `viewer-dist/` by hand.

The build selects the native engine for the current OS and CPU. Its
`--target` option supports `aarch64-macos`, `x86_64-macos`,
`aarch64-linux-gnu`, `x86_64-linux-gnu` and `x86_64-windows`. Availability of
an engine binary does not establish release QA for that target. The binaries
themselves come from pinned builds: `viewer/scripts/refresh-natives.mjs` (the
tjs engine, from [zknpr/txiki.js](https://github.com/zknpr/txiki.js)) and
`viewer/scripts/build-query-plan.mjs` (the query-plan library and sql.js).

## Validating a change

Use a disposable database to reproduce the reported behavior. For data-changing
flows, check both the visible result and the saved database independently with
SQLite. Preserve the existing SQL console, pending-edit behavior, file-ownership
checks and explicit error reporting across native and WASM engines.

`npm run test:gui` exercises the built viewer in headless Chromium and
requires Chrome and the `sqlite3` command. It does not replace testing the
installed app. The [QA records](docs/qa/README.md) list what each release was
checked for, and the [smoke checklist](scripts/qa/smoke-checklist.md) is the
macOS pass to repeat. Keep local screenshots, fixture databases and installers
under the ignored `artifacts/` directory.

Describe the user-visible problem, the change and the validation in each pull
request, and distinguish tests that passed from checks that remain unexecuted.
