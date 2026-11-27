# Third-party distribution notices

The root THIRD_PARTY_NOTICES.txt includes the notice texts for the desktop
viewer, the full locked Cargo dependency graph, and the pinned native runtime.
The Cargo list spans all targets and includes build dependencies. It is not a
list of everything linked into each platform binary.

inventory.json records the original notice-text hashes before aggregation
whitespace normalization, package versions and retrieval URLs. Files absent
from Cargo packages were retrieved from their recorded VCS revision where
available. The winapi target import-library packages use the same project's
MIT/Apache notices; selectors uses the official MPL 2.0 text.

RUST-STDLIB-NOTICES.html and rust-licenses/ preserve the Rust 1.93.0 standard
library's attribution inventory. The HTML also identifies incorporated source
and license terms. Other target toolchains may include a subset or additional
platform runtime components supplied by their operating system.

The viewer list is the npm packages in the esbuild input graphs of the viewer,
worker and native-worker builds (`viewerNpmPackages` in
`viewer/scripts/build.mjs`). The native list uses the
feature selections in the pinned txiki.js artifact workflow, including libuv,
QuickJS, mimalloc, mbedTLS crypto, miniz, SQLite and embedded JavaScript.

A binary release must include the unmodified MPL-covered Cargo source archives,
with SHA256 values matching Cargo.lock; `scripts/release/mpl-sources.mjs`
collects and verifies them. Every package also bundles these notice files. No
AppImage is distributed: its extra bundled Linux system libraries have not been
inventoried.

Update and review the inventory when the dependency locks, the native runtime
pins or packaging change. Preserve upstream copyright and attribution notices.
`scripts/release/notices.mjs` runs in CI and in every release build. It fails
when the inventory's Cargo components differ from the packages a release
resolves, when its viewer npm components differ from the packages the viewer
build bundles, or when an inventoried component has no section in the notices.
No generator is checked in yet: on a failure, add or remove the affected
components and their notice texts by hand, then rerun the check.
