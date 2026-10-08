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

The viewer list comes from the esbuild input graphs for desktop viewer,
worker and native-worker builds. A temporary rebuild at the pinned source
revision reproduced the shipped outputs' hashes. The native list uses the
feature selections in the pinned txiki.js artifact workflow, including libuv,
QuickJS, mimalloc, mbedTLS crypto, miniz, SQLite and embedded JavaScript.

A binary release must include the unmodified MPL-covered Cargo source archives,
with SHA256 values matching Cargo.lock. AppImage redistribution is deferred
until the extra bundled Linux system libraries are inventoried separately.

Regenerate and review the inventory when the source pins, dependency locks or
packaging change. Preserve upstream copyright and attribution notices.
