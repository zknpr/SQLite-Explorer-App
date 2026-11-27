//! Native engine sidecar: lifecycle, framed-JSON proxy, and the OUTER two
//! layers of the desktop's three-layer path authority.
//!
//! The sidecar is the `native/native-worker-desktop.js` bundle that
//! `npm run build:viewer` builds from `viewer/core/native/` (the
//! byte-identical worker method layer over a `tjs:sqlite` sql.js shim), run
//! inside the pinned txiki binary:
//!
//!     tjs run native-worker-desktop.js <dbPath> ro|rw
//!
//! (`tjs.args.slice(3)` — two positional args, NO `--` separator. Exit codes:
//! 0 clean stdin EOF, 1 transport-fatal, 2 usage, 3 ppid-watchdog orphan.)
//!
//! SECURITY MODEL. The webview renders untrusted DB content, so every byte of
//! every `native_rpc` envelope is attacker-controlled in the threat model. A
//! compromised webview must not become an arbitrary file read/write:
//!
//!   layer 1  `native_open` only accepts paths already in the session
//!            allowlist (dialog-picked / OS-delivered — the same gate
//!            `read_database_bytes` uses), then binds the sidecar to the
//!            canonicalised path via argv.
//!   layer 2  (sidecar-side, viewer/core/native) the engine factory refuses any
//!            `initializeDatabase` whose `config.path` differs from its argv
//!            path, refuses rw opens on an `ro` spawn, and blocks the SQL
//!            escape hatches (ATTACH/DETACH, VACUUM INTO) at the shim.
//!   layer 3  `native_rpc` resolves the target sidecar by `DbId` (below),
//!            then parses every envelope and refuses anything it cannot
//!            classify, plus any path-bearing method whose path is not
//!            exactly THAT sidecar's bound path. Fail closed: unparseable or
//!            unlisted envelopes are refused, never forwarded.
//!
//! ROUTING AUTHORITY (N sidecars). The shell holds a registry of open
//! sidecars keyed by an opaque, shell-issued `DbId`, and the DbId — never
//! inference — decides which sidecar an envelope reaches. This matters
//! because most envelopes carry NO path at all (`runQuery`, every mutation,
//! `undoModification`): with more than one sidecar and no id, they would
//! route to whichever one the shell happened to consider current, so DB-A's
//! SQL could read and write DB-B's file. Unknown, closed, and malformed ids
//! are one indistinguishable structured refusal; nothing ever falls back to
//! another sidecar. The webview cannot invent a meaningful id: ids are
//! counter tokens the shell issues only after an open passed layer 1, so they
//! only ever name a sidecar the shell itself bound to an allowlisted path.
//!
//! The Rust side is a FRAMING PROXY, not a codec: payloads are opaque JSON
//! forwarded verbatim (the `__type` BigInt/Uint8Array/Error markers are the
//! webview transport's concern); only `content.messageId` (routing) and the
//! layer-3 fields are ever inspected.
//!
//! SHELL-ORIGINATED EXPORT ROUTE. Exports larger than the 16 MiB frame cap
//! never ride a frame: the two `native_export_*` commands dialog-pick a dest,
//! create a shell-owned 0700 temp directory NEXT TO it, and send the sidecar
//! a `{channel:"shell", content:{kind:"export", …, tempPath}}` request; the
//! sidecar writes the export at that exact path and replies with a path-sized
//! result, which the shell atomically renames into the dest. The envelope is
//! SHELL-CONSTRUCTED and does not pass `gate_envelope` — and, conversely, the
//! gate guarantees no WEBVIEW envelope can ever impersonate it: anything that
//! is not `{channel:"rpc", kind:"invoke", targetMethod ∈ KNOWN_METHODS ∪
//! TRANSPORT_METHODS}` is refused, and the `__shell` messageId namespace is
//! reserved. The webview names NO path anywhere in the export flow (dest is
//! the user's dialog pick, tempPath is the shell's own).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager};

// ---------------------------------------------------------------------------
// Wire constants (must mirror viewer/core/native/frame-codec.js exactly;
// pinned cross-language by viewer/tests/fixtures/native-frames.{bin,json})
// ---------------------------------------------------------------------------

/// Frame = u32 big-endian payload length || UTF-8 JSON payload. The prefix
/// counts the payload only; the 4 header bytes are not included.
pub(crate) const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024; // inclusive, both directions

/// Declared lengths in (cap, 4×cap] are drained-and-resynchronised — the
/// number is plausibly a buggy-but-honest peer's oversized frame and the
/// bytes really are coming, so consuming exactly that many resynchronises at
/// the next frame boundary. Anything above is not a length at all
/// (desync/garbage): draining it would eat the real stream, so the reader
/// stops instead. Same two-tier policy as the JS codec; a Rust reader that
/// drains everything reintroduces the eat-everything bug on this side.
pub(crate) const MAX_DRAIN_BYTES: u64 = 4 * MAX_FRAME_BYTES as u64; // inclusive

/// Mirrors the extension's `INIT_TIMEOUT` (src/nativeWorker.ts): how long
/// `native_open` waits for the spawned sidecar to answer the init ping.
const INIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Grace period between asking a sidecar to exit (stdin EOF) and SIGKILL.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
const EXIT_POLL: Duration = Duration::from_millis(25);

/// Spawn env allowlist, VERBATIM from the extension's `buildSpawnEnv`
/// (src/nativeWorker.ts): the child env is REPLACED, not
/// extended — parent secrets (tokens, cloud creds) must not reach a process
/// that executes attacker-influenced SQL. TMPDIR is load-bearing: the
/// sidecar's exportDatabase writes its VACUUM INTO temp file under it.
#[cfg(not(windows))]
const SPAWN_ENV_ALLOWLIST: [&str; 6] = ["HOME", "TMPDIR", "TZ", "LANG", "LC_ALL", "LC_CTYPE"];
// Windows needs its loader root and temporary-directory variables. Keep the
// same narrow list as the extension instead of inheriting the parent's secrets.
#[cfg(windows)]
const SPAWN_ENV_ALLOWLIST: [&str; 5] = ["SystemRoot", "TEMP", "TMP", "PATH", "PATHEXT"];

#[cfg(not(windows))]
const SIDECAR_BINARY: &str = "tjs";
#[cfg(windows)]
const SIDECAR_BINARY: &str = "tjs.exe";
const SIDECAR_SCRIPT: &str = "native-worker-desktop.js";
#[cfg(target_os = "macos")]
const QUERY_PLAN_LIBRARY: &str = "query-plan.dylib";
#[cfg(target_os = "linux")]
const QUERY_PLAN_LIBRARY: &str = "query-plan.so";
#[cfg(windows)]
const QUERY_PLAN_LIBRARY: &str = "query-plan.dll";

/// Outgoing-frame queue depth, PER SIDECAR (each has its own writer thread
/// and its own queue). The sidecar is a synchronous engine draining stdin
/// sequentially, and the host keeps at most one native frame per database in
/// flight (desktop-host.js chains every call on an entry, both native exports
/// included, from the transport port on), so legitimate in-flight writes are 1
/// per sidecar and ERR_NATIVE_WRITE_BACKPRESSURE is unreachable from a
/// well-behaved page. A value larger than one frame crosses as `nativeTransfer`
/// pieces, each its own frame. The cap stays the shell's own bound, not the
/// page's: it bounds worst-case buffered memory
/// when a hostile or wedged child stops reading: 4 × `MAX_FRAME_BYTES`
/// (16 MiB) = 64 MiB per sidecar, and `MAX_NATIVE_SIDECARS` (16) bounds how
/// many sidecars can exist at once — 1 GiB total, the derivation that fixes
/// that constant.
const WRITE_QUEUE_CAP: usize = 4;

/// Integer messageIds outside ±(2^53 − 1) are refused: the sidecar echoes
/// ids through JS number semantics, so a larger id comes back rounded and
/// the response can never route — the same strand class the float refusal
/// exists to prevent.
const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// messageId namespace reserved for SHELL-originated requests (the init
/// handshake and the export route). `gate_envelope` refuses any webview
/// envelope whose messageId bears this prefix, so a compromised page can
/// neither squat a shell request's pending slot ahead of time (`submit`
/// refuses duplicate ids — a squatted id would DoS the export) nor race a
/// shell-routed reply. The webview's own ids are `rpc_<n>_<ts>`.
const SHELL_MESSAGE_ID_PREFIX: &str = "__shell";

/// messageId of the shell's own init ping. Only live between spawn and open
/// returning, before the sidecar is in the registry at all (so no DbId exists
/// for the webview to aim at it) — and inside the reserved `__shell`
/// namespace like every shell-originated id.
const HANDSHAKE_MESSAGE_ID: &str = "__shell_init_ping";

/// Shell-side backstop on ONE `native_rpc` await (`rpc_awaited`).
///
/// The shell used to rely on a single bound here — "the sidecar's own query
/// deadline stops runaway SQL" — and that deadline is read out of the
/// `initializeDatabase` config, i.e. out of WEBVIEW-supplied data
/// (`MAX_QUERY_TIMEOUT_MS` is why the gate now inspects it). A bound the
/// attacker supplies is not a bound, so the shell keeps its own, independent
/// of anything the page sends. Deliberately well above the gate's ceiling:
/// in normal operation the sidecar's own deadline fires first and this only
/// covers a sidecar that ignores it (or wedges before arming it).
///
/// Expiry costs the sidecar nothing — there is no cancel channel, so it keeps
/// chewing — but it unregisters the pending entry (a late reply then routes
/// nowhere and is logged) and hands the page a structured error instead of a
/// promise that never settles.
const RPC_TIMEOUT: Duration = Duration::from_secs(600);

/// Ceiling the gate enforces on a webview-supplied `initializeDatabase`
/// `config.queryTimeout` (milliseconds). The shipped sidecar arms its query
/// deadline from that field — `Number.isFinite(v) && v > 0 ? v : 30000` — so
/// without this a page could send `1e12` and disarm the only bound the
/// sidecar has on runaway SQL. Absent is fine (the sidecar's own 30 s default
/// applies); present-and-absurd is refused rather than silently clamped,
/// because the envelope is forwarded VERBATIM and rewriting webview bytes at
/// the boundary is a bigger change than refusing them. 5 minutes is two
/// orders of magnitude above the 30 s default and far above any value the
/// viewer's settings modal offers.
const MAX_QUERY_TIMEOUT_MS: f64 = 300_000.0;

/// How long the shell waits for an export-result. Unlike `rpc_awaited`
/// (bounded only by `RPC_TIMEOUT`, ten minutes out), this
/// await MUST be time-bounded: the sidecar's documented behaviour for a
/// shell-channel message it cannot handle (unknown kind, missing id — e.g. a
/// stale pre-export-route bundle) is DROP with only a stderr log, so no
/// fanout would ever resolve the wait. 120 s covers a 512 MiB (the desktop
/// export ceiling) VACUUM INTO / CSV materialisation on the supported
/// hardware with a wide margin. On timeout the temp dir is removed while the
/// sidecar may still hold the file open — POSIX keeps its writes harmless on
/// the unlinked inode, and its late reply routes nowhere (logged, dropped).
const EXPORT_TIMEOUT: Duration = Duration::from_secs(120);

/// Monotonic counter for export messageIds and temp-dir names. Uniqueness
/// within the process is the requirement, not unpredictability: the webview
/// cannot use the `__shell` id namespace at all, and the temp-dir name's
/// unpredictability (pid + seq + nanos, mirroring lib.rs `temp_path_for`)
/// only defends against the park-a-file-on-a-predictable-name save-DoS — the
/// exclusive mkdir is the actual security control.
static EXPORT_SEQ: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Frame codec (Rust side of the pipe)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) enum InboundFrame {
    /// A well-formed frame's payload bytes (≤ cap), boundary-exact.
    Frame(Vec<u8>),
    /// Over-cap but ≤ 4×cap: the payload was consumed and discarded; the
    /// stream is resynchronised at the next frame boundary.
    Drained { declared: u64 },
    /// Impossible declared length (> 4×cap): unrecoverable desync. Nothing
    /// past the header was consumed; the caller must stop reading.
    Desync { declared: u64 },
    /// Clean end of stream (EOF exactly at a frame boundary).
    Eof,
}

/// Reads one frame. The header is read UNSIGNED — `u32::from_be_bytes` cannot
/// go negative, which is precisely why this must never be widened through a
/// signed type: a signed read turns declared lengths ≥ 0x80000000 negative,
/// slips the cap check, and hangs the reader forever (the fixture's
/// `signedTrapHeader` pins this).
pub(crate) fn read_frame(r: &mut impl Read) -> io::Result<InboundFrame> {
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        match r.read(&mut header[filled..]) {
            // EOF before any header byte is the clean end of stream; EOF
            // mid-header means the peer died mid-frame — surfaced, not eaten.
            Ok(0) if filled == 0 => return Ok(InboundFrame::Eof),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sidecar stream ended inside a frame header",
                ))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let declared = u32::from_be_bytes(header) as u64;
    if declared <= MAX_FRAME_BYTES as u64 {
        let mut payload = vec![0u8; declared as usize];
        r.read_exact(&mut payload)?;
        Ok(InboundFrame::Frame(payload))
    } else if declared <= MAX_DRAIN_BYTES {
        // Consume EXACTLY the declared bytes without buffering them. A short
        // count is the peer dying mid-drain — an error, not a resync.
        let copied = io::copy(&mut r.by_ref().take(declared), &mut io::sink())?;
        if copied != declared {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "sidecar stream ended inside an oversized frame being drained",
            ));
        }
        Ok(InboundFrame::Drained { declared })
    } else {
        Ok(InboundFrame::Desync { declared })
    }
}

/// Writes one frame, enforcing the (inclusive) cap on the outgoing payload —
/// the same bound the sidecar enforces on its own sends.
pub(crate) fn write_frame(w: &mut impl Write, payload: &[u8]) -> Result<(), String> {
    if payload.len() as u64 > MAX_FRAME_BYTES as u64 {
        return Err(format!(
            "ERR_NATIVE_FRAME_TOO_LARGE: outgoing envelope is {} bytes; the frame cap is {} bytes (inclusive)",
            payload.len(),
            MAX_FRAME_BYTES
        ));
    }
    let header = (payload.len() as u32).to_be_bytes();
    w.write_all(&header)
        .and_then(|_| w.write_all(payload))
        .and_then(|_| w.flush())
        .map_err(|e| format!("ERR_NATIVE_SIDECAR_EXITED: could not write to the sidecar: {e}"))
}

// ---------------------------------------------------------------------------
// Envelope gate (path-authority layer 3) + messageId routing keys
// ---------------------------------------------------------------------------

/// Routing key for the pending-request map. JSON numbers are normalised
/// (u64 first, i64 for negatives) so an id round-trips to the same key when
/// the sidecar echoes it; non-integer numbers cannot be re-serialised
/// byte-reliably and are refused outbound / logged inbound.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) enum MessageKey {
    UInt(u64),
    Int(i64),
    Str(String),
}

fn message_key_of(id: &serde_json::Value) -> Option<MessageKey> {
    match id {
        serde_json::Value::String(s) => Some(MessageKey::Str(s.clone())),
        serde_json::Value::Number(n) => {
            // Range-limited to the JS safe-integer range — see
            // JS_MAX_SAFE_INTEGER. (The as_i64 branch is only reachable for
            // negatives; non-negatives always satisfy as_u64.)
            if let Some(u) = n.as_u64() {
                (u <= JS_MAX_SAFE_INTEGER).then_some(MessageKey::UInt(u))
            } else {
                n.as_i64()
                    .filter(|i| *i >= -(JS_MAX_SAFE_INTEGER as i64))
                    .map(MessageKey::Int)
            }
        }
        _ => None,
    }
}

/// Every method the worker layer's dispatch table exposes, pinned from
/// `viewer/worker/worker.js` (`const methods = {…}`), the
/// source `native-worker-desktop.js` is built from. scripts/build-viewer.mjs
/// refuses a build whose bundled dispatch table differs from this list.
///
/// PATH AUDIT (layer 3's ground truth — re-verify on every artifact re-pin):
/// the ONLY method whose payload carries a filesystem path consumed as one is
/// `initializeDatabase` — payload is `[filename, config]` where `filename` is
/// a display-only string and `config.path` is the file the engine opens
/// (checked against the bound path below; sidecar layer 2 re-checks it).
/// Verified for the rest: `setPragma` is allowlisted to 7 non-path pragmas
/// with `[a-zA-Z0-9_-]+`-sanitised values; `exportDatabase`/`exportTable`
/// return content in-band (no target path); `refreshFile` takes no arguments;
/// every other payload is table/column/view names, SQL text (path escapes in
/// SQL — ATTACH, VACUUM INTO — are blocked sidecar-side at the shim), record
/// ids, cell values, or byte-count budgets (see the entries). The request a
/// `REQUEST_TRANSFER_METHODS` entry receives in pieces is the same payload,
/// assembled by the sidecar. Methods NOT in this list are refused, not forwarded:
/// a method added to the worker must be re-audited here before the shell will
/// carry it (drift fails loud instead of silently widening the boundary).
const KNOWN_METHODS: [&str; 38] = [
    "initializeDatabase",
    "runQuery",
    "runConsole",
    // 1.8 read workspace: SQL text, positional values and an Explain flag.
    // No file paths; the same bound connection and shim SQL restrictions apply.
    "executeReadQuery",
    "getCellMetadata",
    "openCellReadSession",
    "readCellChunk",
    "closeCellReadSession",
    "exportDatabase",
    "exportTable",
    "fetchTableData",
    "fetchTableCount",
    "fetchSchema",
    "getTableInfo",
    // Snapshot of import destination columns and schema. Table name only;
    // expectedSchemaVersion on importRows is an opaque token, never a path.
    "getImportTarget",
    "getPragmas",
    "setPragma",
    "updateCell",
    "replaceOversizedCell",
    "insertRow",
    // Added in the v1.7.2 merge (2026-09-07), a sibling of `insertRow`:
    // `insertRowWithHistory(table, data, maxEditValueBytes, undoLimit)` — a table
    // name, the row's column values, a byte limit, and the undo limit. It delegates
    // to the same internal insert as `insertRow` with undo-history capture on.
    // THE UNDO LIMIT, the same slot on deleteRows, importRows and updateCellBatch:
    // a bare non-negative byte count (the older form, still accepted), or the
    // object the desktop host now sends, `{limitBytes, reservedBytes, setting,
    // raisable?}`: the configured maxUndoMemory and what the rest of the history
    // entry takes, both byte counts; `setting`, a display string of at most 120
    // characters naming the setting; and `raisable: false` when the limit is at
    // the setting's maximum. The worker only ever uses the last two to word a
    // refusal's message: never a path the sidecar opens, never SQL. The gate checks no
    // argument shapes here, as for every worker method but initializeDatabase.
    // NO filesystem path, so layer 3 needs no path check beyond DbId resolution.
    "insertRowWithHistory",
    // Added with the desktop CSV/JSON import (2026-09-07):
    // `importRows(table, rows, options)` — a table name, an array of
    // `{column: value}` row objects the page mapped from a parsed CSV/JSON
    // source, and an options object of three budgets (`maxEditValueBytes`,
    // `maxUndoSnapshotBytes`, now the undo limit described at insertRowWithHistory,
    // and `maxSnapshotTransportBytes`). It runs every row
    // inside one savepoint and answers the compact post-image set the host
    // records as one undo entry. The FILE never reaches the worker: the shell
    // reads it through `read_import_text` (lib.rs, its own read-only allowlist)
    // and the page parses it. NO filesystem path in the payload, so layer 3
    // needs no path check beyond DbId resolution. On the native engine the host
    // sets `maxSnapshotTransportBytes` to 268435456, the transfer ceiling, where
    // it was 14 MiB: still a byte count.
    "importRows",
    // `deleteRows(table, rowIds, undoLimit)`: the third argument is the undo limit
    // (see insertRowWithHistory), covering the deleted rows. No path.
    "deleteRows",
    "deleteColumns",
    // Audited on admission (the drift pin refused the sync until this entry
    // existed): v1.7.2 replaced `findColumnDependencies` with
    // `findDependentIndexes(table, columns)` — a table name and an array of
    // column-name strings. It validates that shape (assertUsableSqlIdentifier on
    // each) and then only reads `main.sqlite_schema` to list the indexes a column
    // drop would break. It carries NO filesystem path, so layer 3 needs no path
    // check for it beyond the DbId resolution every method already gets.
    "findDependentIndexes",
    "createTable",
    "getViewDefinition",
    "validateViewDefinition",
    "previewViewDefinition",
    "createView",
    "editView",
    "dropView",
    "undoModification",
    "redoModification",
    // `updateCellBatch(table, updates, label, maxEditValueBytes,
    // historyReplayToken, answerToken, undoLimit)`: the seventh argument is the
    // undo limit (see insertRowWithHistory), covering the batch's prior values.
    // The two token slots are worker-internal Symbols a page cannot
    // produce: they cross the JSON lane as null, and null never matches. A null
    // maxEditValueBytes reads as absent. No path.
    "updateCellBatch",
    "addColumn",
    "ping",
    "refreshFile",
];

/// Transport methods native-host.js serves BEFORE the worker's dispatch table
/// (viewer/core/native/native-transfer.js): they move a value larger than one
/// frame in pieces. Not worker methods, so not in KNOWN_METHODS, which the
/// build-viewer drift pin compares with the bundle's dispatch table; build-viewer pins
/// this list against the bundle separately. Every entry needs its own payload check
/// in `gate_envelope`, which refuses one that has none.
///
/// PATH AUDIT: `nativeTransfer` is path-free and carries no SQL authority. Its
/// payload is exactly one of `["push", id, index, parts, length, piece]`,
/// `["pull", id, index]` or `["commit", id]` (`check_native_transfer`). A piece is
/// opaque JSON text the sidecar only concatenates: never consumed as a path, never
/// run as SQL, never loaded. The assembled text is decoded with the frame codec and
/// handed ONLY to the method a later real invoke names, which this gate judges by
/// that invoke's own targetMethod (`REQUEST_TRANSFER_METHODS`). `pull` and `commit`
/// only read or release the sidecar's own parked answer. Every piece is its own
/// frame (at most MAX_FRAME_BYTES) and its own `native_rpc`, so it gets RPC_TIMEOUT
/// and the identity re-stat before and after like any request: a file replaced
/// mid-exchange is refused with ERR_NATIVE_FILE_CHANGED, the page retires the
/// database, the sidecar is closed, and the parked write rolls back with the session.
const TRANSPORT_METHODS: [&str; 1] = ["nativeTransfer"];

/// The worker methods whose request may arrive in pieces: an envelope naming one of
/// them may carry `content.payloadTransfer: {id, length, parts}` in place of
/// `content.payload`, and the sidecar substitutes the payload it assembled from
/// `nativeTransfer` pushes (it refuses the field on every other method too). Pinned
/// against the bundle by build-viewer. Never `initializeDatabase`: the gate reads
/// that method's `config.path` and `config.queryTimeout` from its payload, and a
/// payload in pieces would hide both.
const REQUEST_TRANSFER_METHODS: [&str; 6] = [
    "updateCellBatch",
    "deleteRows",
    "insertRowWithHistory",
    "importRows",
    "undoModification",
    "redoModification",
];

/// The longest value one transfer carries, in UTF-16 code units of JSON text (the
/// sidecar's bound; not pinned by build-viewer).
const MAX_TRANSFER_UNITS: u64 = 256 * 1024 * 1024;

/// The longest transfer piece, in UTF-16 code units: what one frame holds at three
/// UTF-8 bytes per unit after 4 KiB of envelope, the sidecar's own derivation.
const MAX_TRANSFER_PIECE_UNITS: u64 = (MAX_FRAME_BYTES as u64 - 4096) / 3;

/// A transfer id as the sidecar accepts one: 1 to 64 of `[A-Za-z0-9_-]`.
fn transfer_id_ok(value: Option<&serde_json::Value>) -> bool {
    value.and_then(|v| v.as_str()).is_some_and(|id| {
        (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

/// A piece's length in UTF-16 units on the wire and as the sidecar decodes it, or
/// `None` for a wire string the frame codec would not decode to plain text. The codec
/// writes one more `~` before a string that starts with `~` and strips it on read
/// (escapeJsonSafeNumberString / decodeJsonSafeNumberString,
/// viewer/src/core/json-safe-numbers.ts), so a piece led by "~~" decodes one unit shorter
/// than it travels. A single leading `~` is the codec's tag for a non-finite number,
/// never its form of text: such a piece is refused, which is stricter than the
/// sidecar for a hand-made "~x" (it decodes that as itself).
fn piece_units(wire: &str) -> Option<(u64, u64)> {
    let units = wire.encode_utf16().count() as u64;
    if wire.starts_with("~~") {
        Some((units, units - 1))
    } else if wire.starts_with('~') {
        None
    } else {
        Some((units, units))
    }
}

/// The stateless half of the sidecar's own `nativeTransfer` checks; the order of
/// pieces, and that they add up, are its to judge. Counts must be JSON integers
/// (`as_u64` refuses `1.0`, which the page never sends), and the argument count is
/// exact: the page sends six, three and two. A piece is bounded by its length ON THE
/// WIRE, the codec's escape of a leading `~` included: the rule the sidecar
/// applies (wirePieceUnits, viewer/core/native/native-transfer.js) and the page cuts pieces to, so the two
/// sides judge every piece alike. Only its decoded length is compared with the
/// transfer's total, as the sidecar adds up decoded pieces.
fn check_native_transfer(payload: Option<&serde_json::Value>) -> Result<(), String> {
    check_native_transfer_bounded(payload, MAX_TRANSFER_PIECE_UNITS)
}

/// `check_native_transfer` with the piece bound as an argument: the tests judge
/// pieces the viewer's codec wrote at a small bound rather than commit megabytes.
fn check_native_transfer_bounded(payload: Option<&serde_json::Value>, piece_bound: u64) -> Result<(), String> {
    let args = payload.and_then(|p| p.as_array());
    let ok = args.is_some_and(|args| {
        let count = |i: usize| args.get(i).and_then(|v| v.as_u64());
        transfer_id_ok(args.get(1))
            && match (args.first().and_then(|v| v.as_str()), args.len()) {
                (Some("push"), 6) => match (count(2), count(3), count(4), args[5].as_str()) {
                    (Some(index), Some(parts), Some(length), Some(piece)) => {
                        (1..=MAX_TRANSFER_UNITS).contains(&length)
                            && (1..=length).contains(&parts)
                            && index < parts
                            && piece_units(piece).is_some_and(|(wire, decoded)| {
                                wire <= piece_bound && (1..=length).contains(&decoded)
                            })
                    }
                    _ => false,
                },
                (Some("pull"), 3) => count(2).is_some_and(|index| index < MAX_TRANSFER_UNITS),
                (Some("commit"), 2) => true,
                _ => false,
            }
    });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "ERR_NATIVE_ENVELOPE_MALFORMED: nativeTransfer payload must be [\"push\", id, index, parts, length, piece], \
             [\"pull\", id, index] or [\"commit\", id], with id 1-64 of [A-Za-z0-9_-], 1 <= length <= \
             {MAX_TRANSFER_UNITS}, 1 <= parts <= length, index < parts, and a non-empty text piece of at \
             most {piece_bound} UTF-16 units on the wire"
        ))
    }
}

/// `content.payloadTransfer`, judged by presence (the sidecar treats `null` as
/// present). Allowed only where the sidecar assembles a payload, never with
/// `content.payload` beside it, and only in the shape the page sends.
fn check_payload_transfer(
    method: &str,
    content: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let Some(transfer) = content.get("payloadTransfer") else {
        return Ok(());
    };
    // Before the general rule, so a later edit to the list cannot let it through.
    if method == "initializeDatabase" {
        return Err("ERR_NATIVE_ENVELOPE_MALFORMED: initializeDatabase cannot take its payload in pieces: \
             the gate checks its config.path and config.queryTimeout in the payload itself"
            .into());
    }
    if !REQUEST_TRANSFER_METHODS.contains(&method) {
        return Err(format!(
            "ERR_NATIVE_ENVELOPE_MALFORMED: method {method:?} cannot take its payload in pieces"
        ));
    }
    if content.contains_key("payload") {
        return Err(format!(
            "ERR_NATIVE_ENVELOPE_MALFORMED: a {method:?} envelope carries payload or payloadTransfer, never both"
        ));
    }
    let shape = transfer.as_object().filter(|t| t.len() == 3).and_then(|t| {
        Some((t.get("id")?, t.get("length")?.as_u64()?, t.get("parts")?.as_u64()?))
    });
    match shape {
        Some((id, length, parts))
            if transfer_id_ok(Some(id))
                && (1..=MAX_TRANSFER_UNITS).contains(&length)
                && (1..=length).contains(&parts) =>
        {
            Ok(())
        }
        _ => Err(format!(
            "ERR_NATIVE_ENVELOPE_MALFORMED: content.payloadTransfer must be {{id, length, parts}} with id \
             1-64 of [A-Za-z0-9_-], 1 <= length <= {MAX_TRANSFER_UNITS} and 1 <= parts <= length"
        )),
    }
}

/// Layer 3: validates one outgoing envelope against the bound path and
/// returns its routing key. Fail closed on every branch — an envelope this
/// function cannot fully classify is refused, never forwarded. (Refusal also
/// prevents a hang: worker.js silently DROPS envelopes that are not
/// well-formed rpc invokes, which would strand the pending entry forever.)
pub(crate) fn gate_envelope(envelope_json: &str, bound_path: &str) -> Result<MessageKey, String> {
    if envelope_json.len() as u64 > MAX_FRAME_BYTES as u64 {
        return Err(format!(
            "ERR_NATIVE_FRAME_TOO_LARGE: envelope is {} bytes; the frame cap is {} bytes (inclusive)",
            envelope_json.len(),
            MAX_FRAME_BYTES
        ));
    }
    let envelope: serde_json::Value = serde_json::from_str(envelope_json)
        .map_err(|e| format!("ERR_NATIVE_ENVELOPE_MALFORMED: envelope is not valid JSON: {e}"))?;
    if envelope.get("channel").and_then(|v| v.as_str()) != Some("rpc") {
        return Err("ERR_NATIVE_ENVELOPE_MALFORMED: envelope.channel must be \"rpc\"".into());
    }
    let content = envelope
        .get("content")
        .and_then(|v| v.as_object())
        .ok_or("ERR_NATIVE_ENVELOPE_MALFORMED: envelope.content must be an object")?;
    if content.get("kind").and_then(|v| v.as_str()) != Some("invoke") {
        return Err("ERR_NATIVE_ENVELOPE_MALFORMED: only kind \"invoke\" envelopes cross the shell".into());
    }
    let key = content
        .get("messageId")
        .and_then(message_key_of)
        .ok_or("ERR_NATIVE_ENVELOPE_MALFORMED: content.messageId must be a string or integer")?;
    if matches!(&key, MessageKey::Str(id) if id.starts_with(SHELL_MESSAGE_ID_PREFIX)) {
        // The shell's own requests (handshake, export route) ride the same
        // pending map; letting the webview claim ids in that namespace would
        // let it park an entry a future shell submit then collides with.
        return Err(format!(
            "ERR_NATIVE_ENVELOPE_MALFORMED: messageId prefix {SHELL_MESSAGE_ID_PREFIX:?} is reserved for shell-originated requests"
        ));
    }
    let method = content
        .get("targetMethod")
        .and_then(|v| v.as_str())
        .ok_or("ERR_NATIVE_ENVELOPE_MALFORMED: content.targetMethod must be a string")?;
    if !KNOWN_METHODS.contains(&method) && !TRANSPORT_METHODS.contains(&method) {
        return Err(format!(
            "ERR_NATIVE_METHOD_UNLISTED: method {method:?} is not in the shell's audited method list and is not forwarded"
        ));
    }
    check_payload_transfer(method, content)?;
    match method {
        "nativeTransfer" => check_native_transfer(content.get("payload"))?,
        // A transport method admitted without a payload check of its own would
        // reach the sidecar unjudged.
        _ if TRANSPORT_METHODS.contains(&method) => {
            return Err(format!(
                "ERR_NATIVE_METHOD_UNLISTED: transport method {method:?} has no payload check in the shell"
            ))
        }
        _ => {}
    }
    if method == "initializeDatabase" {
        // payload = [filename, config]; the path the engine will open is
        // config.path. The sidecar is bound to exactly one path (its argv),
        // so anything else is a retarget attempt.
        let config = content
            .get("payload")
            .and_then(|v| v.as_array())
            .and_then(|p| p.get(1))
            .and_then(|v| v.as_object())
            .ok_or("ERR_NATIVE_ENVELOPE_MALFORMED: initializeDatabase payload must be [filename, config]")?;
        let path = config
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("ERR_NATIVE_ENVELOPE_MALFORMED: initializeDatabase config.path must be a string")?;
        if path != bound_path {
            return Err(format!(
                "ERR_NATIVE_PATH_MISMATCH: initializeDatabase path {path:?} is not the path this sidecar is bound to"
            ));
        }
        // The sidecar's query deadline is armed from THIS object. It is the
        // only thing that stops a runaway statement inside the child, and it
        // arrives from the page — so the gate validates it rather than
        // forwarding whatever the page chose. Absent is fine: the sidecar
        // falls back to its own 30 s default.
        if let Some(requested) = config.get("queryTimeout") {
            let ms = requested.as_f64().filter(|v| v.is_finite());
            match ms {
                Some(ms) if ms > 0.0 && ms <= MAX_QUERY_TIMEOUT_MS => {}
                _ => {
                    return Err(format!(
                        "ERR_NATIVE_QUERY_TIMEOUT_INVALID: initializeDatabase config.queryTimeout must be a number in (0, {MAX_QUERY_TIMEOUT_MS}] milliseconds; got {requested}"
                    ))
                }
            }
        }
    }
    Ok(key)
}

// ---------------------------------------------------------------------------
// Sidecar core: pending-request map + routing + crash fanout
// ---------------------------------------------------------------------------

type RpcOutcome = Result<String, String>;

/// Where one pending request's answer goes.
///
/// Two flavours because the two kinds of waiter have opposite constraints:
///
/// - `Blocking` — the SHELL's own requests (the init handshake, the export
///   route) and the sync test path. Those wait with `recv_timeout` on a
///   thread they already own, and they are bounded (10 s / 120 s).
/// - `Awaited` — `native_rpc`. A query can legitimately run for minutes, and
///   `#[tauri::command]` bodies run on tauri's shared multi-thread tokio
///   runtime, whose worker count is `available_parallelism()` — SMALLER than
///   `MAX_NATIVE_SIDECARS`. A blocking wait there parks a shared worker for
///   the whole query, so N concurrent slow queries stop every command in
///   every window from dispatching at all. A oneshot the command `.await`s
///   parks nothing: the task yields and the worker goes back to the pool.
///
/// Both are resolved by exactly the same code paths (`route_payload`,
/// `fail_all`), so the crash-fanout guarantee is identical for both.
enum Responder {
    Blocking(mpsc::Sender<RpcOutcome>),
    Awaited(tokio::sync::oneshot::Sender<RpcOutcome>),
}

impl Responder {
    /// Hands the outcome to whoever is waiting. A waiter that already gave up
    /// (dropped its receiver — a timed-out `rpc_awaited`, a cancelled export)
    /// is fine to ignore; the send is the last use of the responder either way.
    fn respond(self, outcome: RpcOutcome) {
        match self {
            Responder::Blocking(tx) => {
                let _ = tx.send(outcome);
            }
            Responder::Awaited(tx) => {
                let _ = tx.send(outcome);
            }
        }
    }
}

type PendingMap = HashMap<MessageKey, Responder>;

pub(crate) struct SidecarCore {
    /// The canonical path this sidecar's argv binds it to; layer 3 compares
    /// against this exact string.
    pub(crate) bound_path: String,
    /// Which FILE `bound_path` named when this sidecar was opened — see
    /// `FileIdentity`. Checked around every envelope (`assert_file_current`),
    /// so a replaced file is refused before the sidecar can touch it. `None`
    /// only for the test fakes, whose bound paths do not exist on disk;
    /// `open_inner`, the sole production constructor, always pins one (a
    /// source-pinned test holds that).
    identity: Option<FileIdentity>,
    pending: Mutex<PendingMap>,
    /// Sender side of the writer thread's bounded frame queue. `None` once
    /// shutdown began (submissions after that fail with a structured error).
    /// The Mutex guards only the Option — it is NEVER held across a pipe
    /// write: the writer thread owns ChildStdin exclusively, so a wedged
    /// 16 MiB `write_all` against a child that stopped reading can park only
    /// that one thread. The kill path needs the Child handle, never this
    /// queue, so shutdown stays bounded regardless of writer state.
    writer_tx: Mutex<Option<mpsc::SyncSender<Vec<u8>>>>,
    /// First failure reason wins; set before the pending map is drained so
    /// `submit` (which checks it under the pending lock) can never insert an
    /// entry that no one will ever resolve.
    dead: Mutex<Option<String>>,
}

impl SidecarCore {
    fn new(
        bound_path: String,
        identity: Option<FileIdentity>,
        writer_tx: mpsc::SyncSender<Vec<u8>>,
    ) -> Self {
        Self {
            bound_path,
            identity,
            pending: Mutex::new(HashMap::new()),
            writer_tx: Mutex::new(Some(writer_tx)),
            dead: Mutex::new(None),
        }
    }

    /// Crash fanout: marks the sidecar dead and resolves EVERY pending
    /// request with a structured error. Idempotent — the first reason wins
    /// and later drains find an empty map. No pending request can hang: any
    /// entry inserted concurrently is either drained here or refused at
    /// insert (see `submit`'s dead-check-under-the-pending-lock).
    pub(crate) fn fail_all(&self, reason: &str) {
        {
            let mut dead = self.dead.lock().unwrap();
            if dead.is_none() {
                *dead = Some(reason.to_string());
            }
        }
        let drained: Vec<(MessageKey, Responder)> =
            self.pending.lock().unwrap().drain().collect();
        for (_key, tx) in drained {
            tx.respond(Err(reason.to_string()));
        }
    }

    /// Read-only views of the two private fields the cross-WINDOW tests in
    /// `lib.rs` assert on (a sibling module cannot reach them directly, only
    /// this module's own `tests` child can). Never compiled into a build the
    /// webview can reach.
    #[cfg(test)]
    pub(crate) fn is_dead(&self) -> bool {
        self.dead.lock().unwrap().is_some()
    }

    #[cfg(test)]
    pub(crate) fn has_no_pending(&self) -> bool {
        self.pending.lock().unwrap().is_empty()
    }

    /// Registers a pending entry and enqueues the frame for the writer
    /// thread. Ordering is load-bearing: the entry is registered BEFORE the
    /// enqueue so a response can never arrive unrouted, and the dead flag is
    /// checked under the pending lock so a concurrent `fail_all` can never
    /// miss the entry. The enqueue is `try_send` on a bounded queue — this
    /// function never blocks on pipe state, so a wedged or hostile child
    /// cannot park async blocking-pool threads here: a full queue fails fast
    /// with a structured error. The page pipelines its requests (nothing
    /// queues them before `native_rpc`; the sidecar runs them one at a time
    /// in arrival order), so the queue fills only once the child stops
    /// draining stdin with the pipe buffer already full: a wedged child, or
    /// one busy in a long statement while large frames wait behind it.
    fn submit(&self, key: MessageKey, envelope: &str) -> Result<mpsc::Receiver<RpcOutcome>, String> {
        let (tx, rx) = mpsc::channel();
        self.submit_with(key, envelope, Responder::Blocking(tx))?;
        Ok(rx)
    }

    /// `submit`'s awaited sibling — see `Responder`. Same registration
    /// ordering, same refusals; only the wake-up mechanism differs.
    fn submit_awaited(
        &self,
        key: MessageKey,
        envelope: &str,
    ) -> Result<tokio::sync::oneshot::Receiver<RpcOutcome>, String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.submit_with(key, envelope, Responder::Awaited(tx))?;
        Ok(rx)
    }

    /// Unregisters a pending entry whose waiter gave up (an `rpc_awaited`
    /// that hit `RPC_TIMEOUT`, an export that hit `EXPORT_TIMEOUT`). Without
    /// this the map would leak an entry per abandoned request and the
    /// messageId would stay occupied for the life of the sidecar; a late
    /// reply for a cancelled id routes nowhere and is logged by
    /// `route_payload`.
    fn cancel(&self, key: &MessageKey) {
        self.pending.lock().unwrap().remove(key);
    }

    fn submit_with(
        &self,
        key: MessageKey,
        envelope: &str,
        responder: Responder,
    ) -> Result<(), String> {
        {
            let mut pending = self.pending.lock().unwrap();
            if let Some(reason) = self.dead.lock().unwrap().as_ref() {
                return Err(reason.clone());
            }
            if pending.contains_key(&key) {
                // Inserting would orphan the first caller's entry; refuse the
                // second instead (a well-behaved host never reuses live ids).
                return Err(format!(
                    "ERR_NATIVE_DUPLICATE_MESSAGE_ID: a request with messageId {key:?} is already pending"
                ));
            }
            pending.insert(key.clone(), responder);
        }
        // Clone the sender out of the lock; the lock never wraps the send.
        let sender = match self.writer_tx.lock().unwrap().as_ref() {
            Some(sender) => sender.clone(),
            None => {
                self.pending.lock().unwrap().remove(&key);
                return Err("ERR_NATIVE_SIDECAR_EXITED: the sidecar's write channel is closed".into());
            }
        };
        match sender.try_send(envelope.as_bytes().to_vec()) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => {
                self.pending.lock().unwrap().remove(&key);
                Err(format!(
                    "ERR_NATIVE_WRITE_BACKPRESSURE: the sidecar is not draining its pipe \
                     ({WRITE_QUEUE_CAP} frames already queued); refusing to buffer more"
                ))
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.pending.lock().unwrap().remove(&key);
                Err("ERR_NATIVE_SIDECAR_EXITED: the sidecar's writer has stopped".into())
            }
        }
    }
}

/// Writer-thread body: sole owner of the child's stdin. Frames are written
/// strictly in queue order. Three exits, all of which drop stdin (the EOF
/// the sidecar exits 0 on):
/// - every queue sender dropped (deliberate shutdown) — queued frames are
///   drained first, so a clean close never loses a written-but-unflushed RPC;
/// - a write error (EPIPE after the child died or was SIGKILLed — which is
///   also what unblocks a `write_all` wedged against a full pipe);
/// - an over-cap frame, unreachable because both submission paths gate the
///   cap before `submit` (`gate_envelope` for webview envelopes,
///   `export_via_sidecar` for shell-originated exports).
///
/// On a write error the WRITER fails all pending itself: a hostile sidecar
/// can half-close its stdin read end while keeping stdout open and staying
/// alive, and in that interleave no reader-side EOF ever fires — without
/// this fanout, queued-but-unwritten requests (and in-flight ones; with
/// stdin gone the session is unusable either way) would park until a later
/// close. The reader-side fanout remains the path for a normal death, which
/// closes stdout too; `fail_all` is idempotent, so overlapping fanouts are
/// harmless.
fn writer_thread(mut stdin: ChildStdin, frames: mpsc::Receiver<Vec<u8>>, core: Arc<SidecarCore>) {
    while let Ok(frame) = frames.recv() {
        if let Err(e) = write_frame(&mut stdin, &frame) {
            eprintln!("[native] sidecar write failed; stopping the writer: {e}");
            core.fail_all(&e);
            return;
        }
    }
}

/// Truncates hostile/oversized payload text for a log line (char-safe).
fn excerpt(text: &str) -> &str {
    match text.char_indices().nth(200) {
        Some((idx, _)) => &text[..idx],
        None => text,
    }
}

/// Routes one inbound payload to its pending request, verbatim. Unroutable
/// frames (messageId null on the sidecar's transport-level error frames —
/// codes ERR_NATIVE_FRAME_TOO_LARGE / _MALFORMED / _DESYNC — or an id nothing
/// is waiting on) are LOGGED, never dropped silently and never fatal.
pub(crate) fn route_payload(core: &SidecarCore, payload: Vec<u8>) {
    let text = match String::from_utf8(payload) {
        Ok(text) => text,
        Err(_) => {
            eprintln!("[native] dropping a sidecar frame whose payload is not valid UTF-8");
            return;
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("[native] unparseable sidecar frame ({e}): {}", excerpt(&text));
            return;
        }
    };
    let key = value
        .pointer("/content/messageId")
        .and_then(message_key_of);
    match key {
        Some(key) => {
            let tx = core.pending.lock().unwrap().remove(&key);
            match tx {
                // Forward the payload BYTES verbatim — never re-serialised,
                // so the webview codec sees exactly what the sidecar sent.
                Some(tx) => tx.respond(Ok(text)),
                None => eprintln!(
                    "[native] sidecar response for unknown messageId {key:?}: {}",
                    excerpt(&text)
                ),
            }
        }
        None => {
            let code = value
                .pointer("/content/error/code")
                .and_then(|v| v.as_str())
                .unwrap_or("no code");
            eprintln!(
                "[native] unroutable sidecar frame (messageId null/invalid, {code}): {}",
                excerpt(&text)
            );
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum LoopEnd {
    Eof,
    Desync { declared: u64 },
    IoError(String),
}

/// The read loop: frames route, oversized frames drain-and-log, a desync or
/// EOF/stream error ends the loop. Pure over `Read` so tests can drive it
/// with in-memory streams.
pub(crate) fn pump_frames(reader: &mut impl Read, core: &SidecarCore) -> LoopEnd {
    loop {
        match read_frame(reader) {
            Ok(InboundFrame::Frame(payload)) => route_payload(core, payload),
            Ok(InboundFrame::Drained { declared }) => eprintln!(
                "[native] drained an oversized {declared}-byte sidecar frame (cap {MAX_FRAME_BYTES}); resynchronised"
            ),
            Ok(InboundFrame::Desync { declared }) => return LoopEnd::Desync { declared },
            Ok(InboundFrame::Eof) => return LoopEnd::Eof,
            Err(e) => return LoopEnd::IoError(e.to_string()),
        }
    }
}

/// Human description of a sidecar exit status, naming the contract's codes.
fn describe_status(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(0) => "exit code 0 (clean EOF shutdown)".into(),
        Some(1) => "exit code 1 (transport-fatal: frame desync or stream error)".into(),
        Some(2) => "exit code 2 (usage: malformed argv, no database was opened)".into(),
        Some(3) => "exit code 3 (orphan watchdog: parent vanished without closing stdin)".into(),
        Some(n) => format!("exit code {n} (unknown)"),
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                format!("killed by signal {:?}", status.signal())
            }
            #[cfg(not(unix))]
            "terminated without an exit code".into()
        }
    }
}

/// Reaps the child: waits up to `grace` for a voluntary exit, then SIGKILLs
/// and waits (never leaves a zombie). `force_now` skips the grace period —
/// used on desync, where the child believes the stream is healthy and would
/// otherwise sit blocked writing into a pipe nobody reads.
fn wait_or_kill(child: &Mutex<Child>, grace: Duration, force_now: bool) -> String {
    let mut child = child.lock().unwrap();
    let deadline = Instant::now() + if force_now { Duration::ZERO } else { grace };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return describe_status(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(EXIT_POLL);
            }
            Err(e) => return format!("wait failed: {e}"),
        }
    }
    if let Err(e) = child.kill() {
        return format!("kill failed: {e}");
    }
    match child.wait() {
        Ok(status) => format!("force-killed; {}", describe_status(status)),
        Err(e) => format!("kill/wait failed: {e}"),
    }
}

/// Reader-thread body: pump until the stream ends, reap the child, then fan
/// the failure out so no pending request is ever left hanging. Any nonzero
/// exit is abnormal and named in the fanout error.
fn reader_thread(mut stdout: ChildStdout, core: Arc<SidecarCore>, child: Arc<Mutex<Child>>) {
    let end = pump_frames(&mut stdout, &core);
    // A pipe that ended because the shell itself initiated a shutdown (dead
    // already set by shutdown_handle / a failed launch) is expected, not a
    // crash — log it quietly instead of as an error.
    let deliberate = core.dead.lock().unwrap().is_some();
    let reason = match end {
        LoopEnd::Eof => {
            let status = wait_or_kill(&child, SHUTDOWN_WAIT, false);
            format!("ERR_NATIVE_SIDECAR_EXITED: the native sidecar closed its pipe ({status})")
        }
        LoopEnd::Desync { declared } => {
            // Unrecoverable by contract: do NOT try to resume. Kill first —
            // the child produced garbage framing and cannot be reasoned with.
            let status = wait_or_kill(&child, SHUTDOWN_WAIT, true);
            format!(
                "ERR_NATIVE_FRAME_DESYNC: the sidecar declared an impossible {declared}-byte frame \
                 (> {MAX_DRAIN_BYTES}); stream unrecoverable, sidecar terminated ({status})"
            )
        }
        LoopEnd::IoError(e) => {
            let status = wait_or_kill(&child, SHUTDOWN_WAIT, false);
            format!("ERR_NATIVE_SIDECAR_EXITED: sidecar pipe error: {e} ({status})")
        }
    };
    if deliberate {
        eprintln!("[native] sidecar reader finished after a deliberate shutdown");
    } else {
        eprintln!("[native] {reason}");
    }
    core.fail_all(&reason);
}

/// Drains the child's stderr into the shell's own stderr. Load-bearing even
/// as pure logging: an undrained pipe fills its kernel buffer and blocks the
/// child's writes forever. Chunked with a fixed buffer rather than
/// line-buffered so a compromised sidecar cannot balloon shell memory with
/// one endless "line" (a multibyte char split across chunk edges degrades to
/// U+FFFD in the log — acceptable for diagnostics).
fn drain_stderr(mut stderr: ChildStderr) {
    let mut buf = [0u8; 8192];
    loop {
        match stderr.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                for line in String::from_utf8_lossy(&buf[..n]).lines() {
                    eprintln!("[native-sidecar] {line}");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // No silent failures: a vanished stderr pipe is expected on
                // child death, but it still gets its one line.
                eprintln!("[native] sidecar stderr pipe error; stopping the drain: {e}");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Artifact resolution + spawn hygiene
// ---------------------------------------------------------------------------

pub(crate) struct NativePaths {
    pub(crate) dir: PathBuf,
}

/// First candidate containing the worker, runtime and bounded query-plan reader.
pub(crate) fn locate_native_dir(candidates: &[PathBuf]) -> Option<NativePaths> {
    candidates
        .iter()
        .find(|dir| {
            dir.join(SIDECAR_BINARY).is_file()
                && dir.join(SIDECAR_SCRIPT).is_file()
                && dir.join(QUERY_PLAN_LIBRARY).is_file()
        })
        .map(|dir| NativePaths { dir: dir.clone() })
}

/// Where the artifacts live: the bundled app's resource dir (shipped via
/// `bundle.resources` mapping `../viewer-dist/native/` → `native/`, which
/// tauri-build also copies next to the dev binary), plus — debug builds
/// only, mirroring how viewer-dist itself is served in dev — the repo
/// checkout's `viewer-dist/native/`. Release binaries never carry the
/// compile-time repo path.
fn native_dir_candidates(app: &AppHandle) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join("native"));
    }
    #[cfg(debug_assertions)]
    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("viewer-dist")
            .join("native"),
    );
    candidates
}

/// Spawns the sidecar with the milestone's spawn hygiene: explicit argv
/// (never a shell), absolute binary and script paths, cwd pinned to the
/// artifact dir, env REPLACED by the allowlist, all three stdio piped.
fn spawn_sidecar(paths: &NativePaths, bound_path: &str, read_only: bool) -> Result<Child, String> {
    // Canonicalise so the argv paths are absolute with no `..` components
    // even when resolved from the dev-repo fallback.
    let dir = fs::canonicalize(&paths.dir)
        .map_err(|e| format!("ERR_NATIVE_UNAVAILABLE: cannot resolve the native artifact dir: {e}"))?;
    let binary = dir.join(SIDECAR_BINARY);
    let script = dir.join(SIDECAR_SCRIPT);
    if !binary.is_absolute() || !script.is_absolute() {
        // Mirrors the extension's "Security Error: Expected absolute path"
        // constructor assertion (src/nativeWorker.ts).
        return Err("ERR_NATIVE_UNAVAILABLE: sidecar paths must be absolute".into());
    }
    let mut cmd = Command::new(&binary);
    #[cfg(windows)]
    let (script_argument, bound_argument) = (
        PathBuf::from(SIDECAR_SCRIPT),
        format!("--path-utf8={}", percent_encoding::utf8_percent_encode(bound_path, percent_encoding::NON_ALPHANUMERIC)),
    );
    #[cfg(not(windows))]
    let (script_argument, bound_argument) = (script, bound_path.to_string());
    // The Windows runtime's argv loses non-ANSI characters. The database path
    // is encoded explicitly; the fixed script name resolves under the pinned cwd.
    // CreateProcessW still receives the binary and cwd as their original paths.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW for the stdio-only child.
    }
    cmd.arg("run")
        .arg(&script_argument)
        .arg(&bound_argument)
        .arg(if read_only { "ro" } else { "rw" })
        .env_clear()
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in SPAWN_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    cmd.spawn()
        .map_err(|e| format!("ERR_NATIVE_SPAWN_FAILED: could not spawn {}: {e}", binary.display()))
}

/// Takes a spawned child's pipes and wires the three service threads
/// (writer, reader, stderr drain) around a fresh `SidecarCore`. Split from
/// `launch_sidecar` so tests can wire a NON-sidecar child (e.g. a process
/// that never drains stdin) without the init handshake.
fn wire_child(
    mut child: Child,
    bound_path: &str,
    identity: Option<FileIdentity>,
) -> Result<(Arc<SidecarCore>, Arc<Mutex<Child>>), String> {
    // These three pipes exist because spawn_sidecar configured them; a
    // missing one is unreachable, but fail closed rather than unwrap.
    let (stdin, stdout, stderr) = match (child.stdin.take(), child.stdout.take(), child.stderr.take()) {
        (Some(i), Some(o), Some(e)) => (i, o, e),
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("ERR_NATIVE_SPAWN_FAILED: sidecar spawned without piped stdio".into());
        }
    };
    let (writer_tx, writer_rx) = mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE_CAP);
    let core = Arc::new(SidecarCore::new(bound_path.to_string(), identity, writer_tx));
    let child = Arc::new(Mutex::new(child));

    {
        let core = Arc::clone(&core);
        std::thread::spawn(move || writer_thread(stdin, writer_rx, core));
    }
    std::thread::spawn(move || drain_stderr(stderr));
    {
        let core = Arc::clone(&core);
        let child = Arc::clone(&child);
        std::thread::spawn(move || reader_thread(stdout, core, child));
    }
    Ok((core, child))
}

/// Spawn + wire threads + init handshake. On any failure the child is killed
/// and reaped before the error returns — no orphaned sidecar can survive a
/// failed open.
pub(crate) fn launch_sidecar(
    paths: &NativePaths,
    bound_path: &str,
    read_only: bool,
    identity: Option<FileIdentity>,
) -> Result<(Arc<SidecarCore>, Arc<Mutex<Child>>), String> {
    let child = spawn_sidecar(paths, bound_path, read_only)?;
    let (core, child) = wire_child(child, bound_path, identity)?;

    // Init handshake: `ping` is a real worker method that answers without a
    // database, so one routed response proves the whole pipeline — process
    // up, transport framing intact in both directions, dispatch and method
    // layer live. Without it, a dead-on-arrival sidecar (bad artifact, exec
    // failure, instant exit 2) would surface only as the FIRST real RPC
    // hanging into the webview's own timeout.
    let handshake = serde_json::json!({
        "channel": "rpc",
        "content": {
            "kind": "invoke",
            "messageId": HANDSHAKE_MESSAGE_ID,
            "targetMethod": "ping",
            "payload": []
        }
    })
    .to_string();
    let key = MessageKey::Str(HANDSHAKE_MESSAGE_ID.to_string());
    let outcome = match core.submit(key.clone(), &handshake) {
        Ok(rx) => match rx.recv_timeout(INIT_TIMEOUT) {
            Ok(outcome) => outcome,
            Err(_) => {
                core.cancel(&key);
                Err(format!(
                    "ERR_NATIVE_INIT_TIMEOUT: the sidecar did not answer the init ping within {}s",
                    INIT_TIMEOUT.as_secs()
                ))
            }
        },
        Err(e) => Err(e),
    };
    if let Err(e) = outcome {
        let status = wait_or_kill(&child, SHUTDOWN_WAIT, true);
        core.fail_all(&e);
        eprintln!("[native] init handshake failed ({e}); sidecar reaped: {status}");
        return Err(e);
    }
    Ok((core, child))
}

// ---------------------------------------------------------------------------
// File identity — external replacement detection
// ---------------------------------------------------------------------------

/// Which FILE a bound path named when its sidecar was opened: device + inode.
///
/// The sidecar keeps an open descriptor on the file. If something replaces the
/// file at that path — an atomic rename over it (every editor's "safe save",
/// `mv new.db x.db`), a move, a delete — the descriptor still points at the
/// OLD inode: every later statement, a COMMIT above all, lands where the user
/// cannot see it, and the shell would report "saved". So the identity is
/// pinned at open and compared around every envelope (`assert_file_current`),
/// and a mismatch is refused with `ERR_NATIVE_FILE_CHANGED` before the sidecar
/// sees the envelope; the page retires the database and offers Reload.
///
/// Deliberately NOT size or mtime. Both change on every ordinary SQLite write —
/// another process's DML, a WAL checkpoint, VACUUM — none of which change the
/// inode and none of which make the sidecar's handle wrong; SQLite itself is
/// built for concurrent writers. Only replacement changes or loses the inode.
/// Same rule as the VS Code host's `sameNativeFileIdentity` (nativeWorker.ts):
/// "Size and timestamps change during ordinary SQLite DML and checkpoints."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    dev: u64,
    ino: u128,
}

impl FileIdentity {
    /// `stat` on the path, following symlinks: `bound_path` is canonical with
    /// no final-component symlink at open (`resolve_bound_path`), so a symlink
    /// planted there later resolves to a DIFFERENT inode and is refused too.
    /// A non-regular file is refused rather than identified.
    pub(crate) fn of(path: &Path) -> Result<Self, String> {
        #[cfg(windows)]
        {
            let file = crate::regular_read_options().open(path).map_err(|e| e.to_string())?;
            let meta = file.metadata().map_err(|e| e.to_string())?;
            Self::of_file(path, &file, &meta)
        }
        #[cfg(unix)]
        {
            let meta = fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
            Self::of_metadata(path, &meta)
        }
    }

    #[cfg(unix)]
    fn of_metadata(path: &Path, meta: &fs::Metadata) -> Result<Self, String> {
        if !meta.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino() as u128,
        })
    }

    #[cfg(windows)]
    fn of_file(path: &Path, file: &fs::File, meta: &fs::Metadata) -> Result<Self, String> {
        if !meta.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let (dev, ino) = crate::windows_file_info::identity(file)?;
        Ok(Self { dev, ino })
    }
}

/// Admits the file at `bound` for a native open: it must be a regular file
/// within the configured `max_bytes` (0/None = unlimited — the same bound the
/// WASM lane's read enforces, so no engine can admit a file the other refused),
/// and its identity is pinned from the SAME `stat` so nothing can slip between
/// the size check and the pin. Runs BEFORE any hold is claimed or child is
/// spawned: a refused open leaves nothing to release or reap.
pub(crate) fn admit_file(bound: &Path, max_bytes: Option<u64>) -> Result<FileIdentity, String> {
    #[cfg(windows)]
    let file = crate::regular_read_options().open(bound)
        .map_err(|e| format!("ERR_NATIVE_PATH_NOT_ALLOWED: cannot open {}: {e}", bound.display()))?;
    #[cfg(windows)]
    let meta = file.metadata().map_err(|e| format!("ERR_NATIVE_PATH_NOT_ALLOWED: {e}"))?;
    #[cfg(unix)]
    let meta = fs::metadata(bound).map_err(|e| {
        format!(
            "ERR_NATIVE_PATH_NOT_ALLOWED: cannot stat {}: {e}",
            bound.display()
        )
    })?;
    #[cfg(unix)]
    let identity = FileIdentity::of_metadata(bound, &meta);
    #[cfg(windows)]
    let identity = FileIdentity::of_file(bound, &file, &meta);
    let identity = identity
        .map_err(|e| format!("ERR_NATIVE_PATH_NOT_ALLOWED: {e}"))?;
    crate::assert_within_size_limit(meta.len(), max_bytes)?;
    Ok(identity)
}

fn file_changed_error(bound: &str, detail: &str) -> String {
    format!(
        "ERR_NATIVE_FILE_CHANGED: the database file at {bound} is no longer the file this sidecar opened ({detail}): it was replaced, moved, or deleted outside SQLite Explorer"
    )
}

/// Refuses when `bound_path` no longer names the file the sidecar opened —
/// the pre-check of every envelope (so the sidecar never executes against an
/// orphaned inode) and the post-check of every answer (so a replacement that
/// landed DURING the statement is reported instead of a stale success: dev's
/// `withCurrentFile` checks both sides for the same reason). A bounded local
/// `stat` per envelope; orders of magnitude under the RPC it guards.
fn assert_file_current(core: &SidecarCore) -> Result<(), String> {
    let Some(opened) = core.identity else {
        return Ok(()); // unpinned: test fakes only (see SidecarCore::identity)
    };
    match FileIdentity::of(Path::new(&core.bound_path)) {
        Ok(current) if current == opened => Ok(()),
        Ok(_) => Err(file_changed_error(
            &core.bound_path,
            "device/inode differ from the file opened",
        )),
        Err(detail) => Err(file_changed_error(&core.bound_path, &detail)),
    }
}

// ---------------------------------------------------------------------------
// Managed state + path-authority layer 1
// ---------------------------------------------------------------------------

struct SidecarHandle {
    core: Arc<SidecarCore>,
    child: Arc<Mutex<Child>>,
    /// The app-global "this window has that file open" hold this sidecar
    /// carries, if it is a read-write session. Released by `Drop`, so EVERY
    /// path that removes a handle from a registry — `close_inner`, the
    /// window-destroyed drain, the page-load reap, app exit, and a refused
    /// `register_sidecar` — releases it without having to remember to.
    _native_hold: Option<NativeHold>,
}

impl SidecarHandle {
    /// A registry entry with no app-global hold attached. Only the tests
    /// build handles directly (`open_inner` is the sole production
    /// constructor, and it always attaches the hold for a read-write open).
    #[cfg(test)]
    fn unclaimed(core: Arc<SidecarCore>, child: Arc<Mutex<Child>>) -> Self {
        Self {
            core,
            child,
            _native_hold: None,
        }
    }
}

/// APP-GLOBAL: canonical database path → the ONE window that currently has
/// that file open, whichever engine is serving it.
///
/// WHY IT EXISTS. The per-window registries are deliberately isolated (a DbId
/// issued in one window must never resolve in another), and the page-side
/// host dedupes opens by canonical path within ITS OWN window. Neither of
/// those can see the case this exists for: window A and window B opening the
/// SAME file. Two editable copies of one database is silent data loss — under
/// the WASM engine the whole-image save simply overwrites the other window's
/// edits, and under the native engine two rw SQLite connections interleave
/// transactions from two independent undo histories.
///
/// TWO KINDS OF EVIDENCE, ONE REGISTRY. The shell can observe the native
/// engine's open/close pair directly, so a native open takes a `NativeHold`
/// that only the shell can set and only `Drop` can clear. It can observe no
/// such pair for the WASM engine — there is no "the page closed this
/// database" command, and a hold taken at `read_database_bytes` with no
/// release would make an ordinary close-then-reopen-elsewhere fail forever.
/// The WASM lane is therefore covered by what the page PUSHES: every registry
/// change already calls `notifyDatabasesChanged` → `set_unsaved_state`, and
/// that push now carries the window's whole open-path set, which
/// {@link sync_reported} installs WHOLESALE. A close drops out of the next
/// push and releases itself; nothing has to be remembered or unwound.
///
/// The push cannot arrive before the open it describes, so
/// {@link hold_for_read} takes a short-lived PROVISIONAL hold at read time to
/// close that window. It expires ({@link PROVISIONAL_HOLD_TTL}) precisely so
/// that a read whose open then failed — or a page that never pushes at all —
/// cannot strand a file for the rest of the session.
///
/// TRUST. A page can only ever narrow ITS OWN window's set: `sync_reported`
/// touches no entry owned by another window, and it can neither set nor clear
/// the `native` flag. A compromised page under-reporting its own open files
/// is the same self-inflicted loss as a compromised page discarding the
/// user's buffer directly — it owns them either way (the same argument
/// `set_unsaved_state`'s doc comment makes about the unsaved count).
///
/// This is the one piece of native state that MUST be app-global: it is the
/// only place with a view across windows. It grants nothing and routes
/// nothing — it can only ever refuse.
#[derive(Default, Clone, Debug)]
pub struct OpenFiles(Arc<Mutex<OpenFilesInner>>);

#[derive(Default, Debug)]
struct OpenFilesInner {
    /// canonical path → who has it open.
    holders: HashMap<PathBuf, Holder>,
    /// window label → the exact spellings that window's last push named, each
    /// mapped to the canonical path it resolved to. It is both the record of
    /// what that window reports AND a `realpath` cache: an unchanged list
    /// re-pushed costs no filesystem I/O at all, which matters because the
    /// push lands on the main thread (see `set_unsaved_state`).
    reported: HashMap<String, HashMap<PathBuf, PathBuf>>,
}

#[derive(Debug)]
struct Holder {
    /// The window that owns every hold on this path. One window at a time —
    /// that IS the invariant this registry exists to keep.
    window: String,
    /// A live native sidecar has this file open read-write. Shell-observed:
    /// set by `claim_native`, cleared only by `NativeHold::drop`. No page
    /// push can set or clear it.
    native: bool,
    /// The page-side hold, which is what covers the WASM engine.
    page: Option<PageHold>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageHold {
    /// Taken by `read_database_bytes`, before any push could have reported
    /// the open. EXPIRES — see `PROVISIONAL_HOLD_TTL`.
    Provisional(Instant),
    /// The window's last push named this path. Does NOT expire: the push is
    /// event-driven, not a heartbeat, so a window with one file open and idle
    /// for an hour is still holding it. Released by the next push that omits
    /// it, by a page load, or by the window going away.
    Reported,
}

/// How long a read-time hold survives without a push confirming it.
///
/// The bound has to cover "bytes handed to the page → sql.js parsed them →
/// the entry was committed → `notifyDatabasesChanged` ran", on an image that
/// is already in memory. A minute is far more than that and still short
/// enough that a page which dies mid-open cannot lock the user out of their
/// own file for a session. The common failure — an open that throws — does
/// not wait it out at all: the host pushes from its failure path, which
/// releases the hold immediately.
const PROVISIONAL_HOLD_TTL: Duration = Duration::from_secs(60);

/// Ceiling on how many paths one push may report. The host's own cap is 16
/// open databases per window (`MAX_OPEN_DATABASES`), so this is generous
/// headroom, not a limit a real page meets.
///
/// An over-cap push is REJECTED WHOLE rather than truncated, and that
/// direction is deliberate: truncating would silently release the holds past
/// the cap, which is the failure this registry exists to prevent. Keeping the
/// previous set can only ever leave a stale REFUSAL standing, which is the
/// safe way to be wrong.
const MAX_REPORTED_OPEN_PATHS: usize = 64;

impl Holder {
    fn live_at(&self, now: Instant) -> bool {
        self.native
            || match self.page {
                Some(PageHold::Reported) => true,
                Some(PageHold::Provisional(deadline)) => deadline > now,
                None => false,
            }
    }
}

impl OpenFilesInner {
    /// Drops every entry that no longer holds anything — an expired
    /// provisional, or a native hold released while nothing else referenced
    /// the path. Run at the head of every operation so the map stays the size
    /// of what is actually open rather than growing for the life of the
    /// process.
    fn prune(&mut self, now: Instant) {
        self.holders.retain(|_, holder| holder.live_at(now));
    }

    /// The window holding `canonical`, if any is still live.
    #[cfg(test)]
    fn owner(&self, canonical: &Path, now: Instant) -> Option<&str> {
        self.holders
            .get(canonical)
            .filter(|holder| holder.live_at(now))
            .map(|holder| holder.window.as_str())
    }
}

/// One live native hold. Dropping it releases the file's native flag.
#[derive(Debug)]
pub(crate) struct NativeHold {
    files: OpenFiles,
    path: PathBuf,
    /// The window this hold was taken for. Checked on release: a window
    /// teardown clears that window's entries eagerly, and a detached reaper
    /// can then drop this guard LONG after another window has legitimately
    /// taken the same file. Without the label check that late drop would
    /// silently delete the new owner's hold.
    window: String,
}

impl Drop for NativeHold {
    fn drop(&mut self) {
        let mut inner = self.files.0.lock().unwrap();
        let still_held = match inner.holders.get_mut(&self.path) {
            Some(holder) if holder.window == self.window => {
                holder.native = false;
                holder.live_at(Instant::now())
            }
            // Someone else owns the entry now (see the `window` field): not
            // ours to touch.
            _ => return,
        };
        if !still_held {
            inner.holders.remove(&self.path);
        }
    }
}

/// The refusal every entry point shares, so the user reads the same sentence
/// whichever engine the host happened to try. Names the file, says where it
/// is open, and says what to do about it. Deliberately does NOT name the
/// other window's label — it is an internal identifier and means nothing to
/// the user.
fn already_open_error(path: &Path, owner: &str, here: &str) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    let where_ = if owner == here {
        "already open in this window".to_string()
    } else {
        "already open in another SQLite Explorer window".to_string()
    };
    format!(
        "ERR_NATIVE_DB_ALREADY_OPEN: \"{name}\" is {where_}. Close it there before opening it here \
         — two editable copies of one database would silently overwrite each other's changes."
    )
}

/// A directory entry's identity, a link at the final component identified as itself
/// rather than its target: device and inode on Unix, volume serial and 128-bit file id
/// on Windows.
fn entry_identity(path: &Path) -> io::Result<(u64, u128)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(path)?;
        Ok((meta.dev(), meta.ino() as u128))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        };
        // Attributes only, no data access. BACKUP_SEMANTICS opens a folder as well,
        // OPEN_REPARSE_POINT the link itself rather than its target.
        let handle = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        crate::windows_file_info::identity(&handle).map_err(io::Error::other)
    }
}

/// Whether `dest` is, as its volume resolves names, a database in `held` or one of that
/// database's `-wal`, `-shm` or `-journal`. Every comparison is by no-follow identity,
/// with the volume resolving the spelling: that is what makes "É.db" and "é.db" on a
/// case-insensitive volume, or the NFC and NFD spellings of one name on APFS, the one
/// file they are on disk, and no fold done here could match every volume's.
///
/// - The destination's own entry, when it exists, is compared with every open database
///   and with every journal file those databases have now, looked up under their own
///   names. That covers every spelling the volume resolves to an existing journal: APFS
///   folds U+017F (long s) onto s, so "x.db-ſhm" IS the live "x.db-shm", and a write
///   there replaced the wal-index another connection was using.
/// - A journal name that does not exist yet can only be matched by spelling: the
///   destination's name minus each journal suffix it ends with in any ASCII case
///   (refusing `x.db-WAL` beside an open `x.db` on a case-sensitive volume is the safe
///   way to be wrong) is looked up and compared with the open databases. U+017F (long
///   s) counts as an s there: measured on APFS, it is the only one-code-point non-ASCII
///   spelling of any suffix letter (every code point to U+2FFFF probed), and matching it
///   before a `-shm` exists keeps a connection that opens the database in WAL mode while
///   the write is under way from having its new `-shm` replaced through it. A file at a
///   `-shm` name nothing had used is harmless in itself, because the first connection to
///   open the database in WAL mode truncates the `-shm` before reading it (a database
///   image written there left the data intact). Not measured: multi-code-point
///   spellings, the hyphen, NTFS's own folding, and arbitrary bytes at a `-wal` or
///   `-journal` name, which SQLite would read if they were a valid log.
///
/// Identity cannot tell one link to a file from another, so a hard link to an open
/// database is refused too, though writing there would only replace that link. Only
/// "no such file" means no clash; any other failure refuses, since a destination that
/// cannot be looked at cannot be known not to be open.
/// Where a journal `suffix` (`-wal`, `-shm`, `-journal`) starts at the end of a name's
/// encoded bytes, if the name ends with it after a non-empty prefix: letters in any
/// ASCII case, and an s also as U+017F (encoded C5 BF), the one spelling APFS folds onto
/// a suffix letter (see `open_database_refusal`). The leading '-' is matched as itself.
fn journal_suffix_cut(bytes: &[u8], suffix: &str) -> Option<usize> {
    const LONG_S: [u8; 2] = [0xC5, 0xBF];
    let mut end = bytes.len();
    for &want in suffix.as_bytes().iter().rev() {
        if want == b's' && end >= 2 && bytes[end - 2..end] == LONG_S {
            end -= 2;
        } else if end >= 1 && bytes[end - 1].eq_ignore_ascii_case(&want) {
            end -= 1;
        } else {
            return None;
        }
    }
    (end > 0).then_some(end)
}

fn open_database_refusal(held: &[PathBuf], folder: &Path, dest_name: &std::ffi::OsStr) -> Option<String> {
    let name = dest_name.to_string_lossy();
    let unchecked = |e: io::Error| {
        format!(
            "ERR_DESTINATION_UNCHECKED: SQLite Explorer could not check whether \"{name}\" is a \
             database open in it, or one of its journal files ({e}), so it did not write there. \
             Choose another location."
        )
    };
    // An open database's own entry could not be looked at (its share went away, or
    // it lost search permission). Still a refusal, but naming which one, by file name
    // only: this sentence can reach a page in another window.
    let held_unchecked = |held: &Path, e: io::Error| {
        let held = held.file_name().map_or_else(|| "an open database".into(), |n| n.to_string_lossy());
        format!(
            "ERR_DESTINATION_UNCHECKED: SQLite Explorer could not check whether \"{name}\" is the \
             open database \"{held}\" or one of its journal files ({e}), so it did not write there. \
             Save under a name that does not exist yet, or close \"{held}\" (or make its folder \
             reachable again) and try again."
        )
    };
    let bytes = dest_name.as_encoded_bytes();
    // Looked up only once a candidate exists, so a Save As under a new name never
    // touches the volume an open database is on.
    let mut open_ids: Option<Vec<(u64, u128)>> = None;
    let mut journal_ids: Option<Vec<(u64, u128)>> = None;
    let open_refusal = || {
        format!(
            "ERR_DESTINATION_OPEN: \"{name}\" is a database open in SQLite Explorer, or one of its \
             journal files, so writing there would replace it. Choose another name (Save writes \
             the open database itself)."
        )
    };
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let base = if suffix.is_empty() {
            dest_name
        } else {
            let Some(cut) = journal_suffix_cut(bytes, suffix) else { continue };
            // SAFETY: `cut` is immediately before the suffix's leading '-' just
            // matched, an ASCII byte after a non-empty prefix, which is where an
            // OsStr's encoded bytes may be split.
            unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(&bytes[..cut]) }
        };
        let candidate = match entry_identity(&folder.join(base)) {
            Ok(id) => id,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Some(unchecked(e)),
        };
        if open_ids.is_none() {
            let mut ids = Vec::with_capacity(held.len());
            for path in held {
                match entry_identity(path) {
                    Ok(id) => ids.push(id),
                    // Gone from its name since it was opened: nothing found at a
                    // destination is that file.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Some(held_unchecked(path, e)),
                }
            }
            open_ids = Some(ids);
        }
        if open_ids.as_ref().is_some_and(|ids| ids.contains(&candidate)) {
            return Some(open_refusal());
        }
        // The destination's own entry exists: compare it with the journal files the
        // open databases have now, whatever spelling it was reached by.
        if suffix.is_empty() {
            if journal_ids.is_none() {
                let mut ids = Vec::new();
                for path in held {
                    let Some(held_name) = path.file_name() else { continue };
                    for journal in ["-wal", "-shm", "-journal"] {
                        let mut journal_name = held_name.to_os_string();
                        journal_name.push(journal);
                        match entry_identity(&path.with_file_name(journal_name)) {
                            Ok(id) => ids.push(id),
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                            Err(e) => return Some(held_unchecked(path, e)),
                        }
                    }
                }
                journal_ids = Some(ids);
            }
            if journal_ids.as_ref().is_some_and(|ids| ids.contains(&candidate)) {
                return Some(open_refusal());
            }
        }
    }
    None
}

/// Why an export or Save As must not write `dest`: it is a database open in
/// any window of this app, or that database's `-wal`, `-shm` or `-journal`;
/// or a log SQLite would apply to it sits beside it (`crate::log_beside`).
/// Writing over the first replaces a file an engine has open; a file under one
/// of the others would be read as that database's journal on its next open;
/// and a new file under a live or leftover log would be read with that log's
/// pages, whether or not the program that wrote it is still running.
pub(crate) fn destination_refusal(files: &OpenFiles, dest: &Path) -> Option<String> {
    // A path with no final name names no file to check: refused, not let through.
    let Some(dest_name) = dest.file_name() else {
        return Some(format!("ERR_DESTINATION_UNCHECKED: {} names no file to write.", dest.display()));
    };
    let name = dest_name.to_string_lossy().into_owned();
    let folder = dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    // On Windows every rule below judges the name Win32 will write (`win32_final_name`).
    #[cfg(windows)]
    let written = match win32_final_name(dest_name) {
        Ok(written) => written,
        Err((code, why)) => return Some(format!("{code}: \"{name}\" {why}, so SQLite Explorer did not write there.")),
    };
    #[cfg(windows)]
    let dest_name = written.as_os_str();
    #[cfg(windows)]
    let dest = &folder.join(dest_name);
    // The held paths are copied out and the lock released before anything is
    // stat-ed: set_unsaved_state takes this lock on the main thread, and a
    // volume that stops answering must not freeze every window.
    let held: Vec<PathBuf> = {
        let mut inner = files.0.lock().unwrap();
        inner.prune(Instant::now());
        inner.holders.keys().cloned().collect()
    };
    // The name as written, and on Windows, when something is already there, its long
    // name too: an 8.3 short name ("XDB-WA~1" for x.db-wal) names the same file but
    // none of the spellings the rules match.
    #[cfg(windows)]
    let spellings = match destination_spellings(dest_name, crate::windows_file_info::long_name(dest)) {
        Ok(spellings) => spellings,
        Err(e) => {
            return Some(format!(
                "ERR_DESTINATION_UNCHECKED: SQLite Explorer could not read the long name of \"{name}\" ({e}), \
                 so it did not write there. Choose another location."
            ))
        }
    };
    #[cfg(not(windows))]
    let spellings = vec![dest_name.to_os_string()];
    if let Some(refusal) = named_destination_refusal(&held, folder, &spellings, &name) {
        return Some(refusal);
    }
    // After the open-files check, and reached whatever it found short of a
    // refusal: an open database with a live WAL is named as the open one, not
    // as a file some other program holds. Beside every spelling: an 8.3 short
    // name's own log names are not the ones SQLite keeps for the long name.
    let beside: Vec<PathBuf> =
        std::iter::once(dest.to_path_buf()).chain(spellings.iter().skip(1).map(|spelling| folder.join(spelling))).collect();
    destination_log_refusal(&beside, &name)
}

/// The refusal for a log SQLite would apply to a file written at any of `paths` (the
/// destination under each spelling of its name), named for the user as `name`.
fn destination_log_refusal(paths: &[PathBuf], name: &str) -> Option<String> {
    for path in paths {
        let log = match crate::log_beside_destination(path) {
            Ok(log) => log,
            Err(unchecked) => {
                return Some(format!(
                    "ERR_DESTINATION_UNCHECKED: SQLite Explorer could not check \"{name}\" for a log SQLite \
                     would apply to the new file ({unchecked}), so it did not write there. Choose another \
                     location."
                ))
            }
        };
        if let Some(log) = log {
            let what = match log {
                crate::LogBeside::Wal => "a -wal file holding frames",
                crate::LogBeside::LiveWal => "a WAL log another program is writing",
                crate::LogBeside::Journal => "a rollback journal",
            };
            return Some(format!(
                "ERR_DESTINATION_HAS_LOG: \"{name}\" has {what} beside it, which SQLite would apply to \
                 the new file the next time it is opened. Choose another name, or close the program that \
                 has it open and try again."
            ));
        }
    }
    None
}

/// The rules a destination's name is judged by, for each spelling of it: as written,
/// and on Windows its long name too (`destination_spellings`). The first refusal any
/// spelling draws is the answer.
fn named_destination_refusal(held: &[PathBuf], folder: &Path, spellings: &[std::ffi::OsString], name: &str) -> Option<String> {
    for spelling in spellings {
        if !held.is_empty() {
            if let Some(refusal) = open_database_refusal(held, folder, spelling) {
                return Some(refusal);
            }
        }
        if let Some(refusal) = journal_name_refusal(folder, spelling, name) {
            return Some(refusal);
        }
    }
    None
}

/// The spellings a destination is judged by: `written`, and `long` (the long name
/// of what is already at it, on Windows) when that is another. A long name that
/// could not be read is the caller's to refuse.
#[cfg(any(windows, test))]
fn destination_spellings(
    written: &std::ffi::OsStr,
    long: io::Result<Option<std::ffi::OsString>>,
) -> io::Result<Vec<std::ffi::OsString>> {
    let mut spellings = vec![written.to_os_string()];
    if let Some(long) = long? {
        if long != written {
            spellings.push(long);
        }
    }
    Ok(spellings)
}

/// A name SQLite reads as a journal of the database whose name it starts with
/// (x.db-wal is x.db's) is refused, whatever is open, when that database is there:
/// whatever is written here is read as part of it the next time anything opens it.
/// The suffix is matched by the open databases' spelling rule (`destination_refusal`
/// runs that check first, so that an open one is still named as open), and the name
/// it leaves is looked up by the volume, so the volume decides whether a spelling is
/// there. Only nothing of that name, or something there that is not a file, admits;
/// any other lookup failure refuses as unchecked.
fn journal_name_refusal(folder: &Path, dest_name: &std::ffi::OsStr, name: &str) -> Option<String> {
    let encoded = dest_name.as_encoded_bytes();
    for suffix in ["-wal", "-shm", "-journal"] {
        let Some(cut) = journal_suffix_cut(encoded, suffix) else { continue };
        // SAFETY: `cut` is immediately before the suffix's leading '-', an ASCII
        // byte after a non-empty prefix, which is where an OsStr's encoded bytes may
        // be split.
        let base = unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(&encoded[..cut]) };
        let base_name = base.to_string_lossy();
        // A regular file, or a link to one, is what SQLite could open as that database;
        // a folder, a link to nothing, or anything else under the name is not.
        let base_path = folder.join(base);
        let database_there = match fs::symlink_metadata(&base_path) {
            Ok(meta) if meta.file_type().is_symlink() => fs::metadata(&base_path).map(|target| target.is_file()),
            Ok(meta) => Ok(meta.is_file()),
            Err(e) => Err(e),
        };
        match database_there {
            Ok(false) => {}
            Ok(true) => {
                return Some(format!(
                    "ERR_DESTINATION_JOURNAL_NAME: \"{name}\" ends in {suffix} and \"{base_name}\" is beside it, \
                     so SQLite would read a file written there as part of \"{base_name}\". Choose a name \
                     without that ending."
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Some(format!(
                    "ERR_DESTINATION_UNCHECKED: SQLite Explorer could not check whether \"{base_name}\" is \
                     beside \"{name}\" ({e}), which SQLite would then read as its journal, so it did not \
                     write there. Choose another location."
                ))
            }
        }
    }
    None
}

/// A destination's final name as Win32 resolves it before any file system sees it:
/// trailing dots and spaces dropped, and a trailing "::$DATA" (the file's own data
/// stream, in any case) taken as the file itself, until neither applies. So
/// "x.db-shm.", "x.db-journal " and "x.db-wal::$DATA" are those journal files. A name
/// that is then empty names no file, and one that still has a ':' names an alternate
/// data stream, never a sensible database; the `Err` carries the refusal's code and
/// reason. Applied on Windows only, where it is what the write will name: on Unix
/// those characters are part of the name, and a lookup of the normalized name would
/// examine another file than the one written.
#[cfg(any(windows, test))]
fn win32_final_name(name: &std::ffi::OsStr) -> Result<std::ffi::OsString, (&'static str, &'static str)> {
    const DATA_STREAM: &[u8] = b"::$DATA";
    let mut bytes = name.as_encoded_bytes();
    loop {
        let before = bytes.len();
        while let [rest @ .., b'.' | b' '] = bytes {
            bytes = rest;
        }
        if bytes.len() >= DATA_STREAM.len() && bytes[bytes.len() - DATA_STREAM.len()..].eq_ignore_ascii_case(DATA_STREAM) {
            bytes = &bytes[..bytes.len() - DATA_STREAM.len()];
        }
        if bytes.len() == before {
            break;
        }
    }
    if bytes.is_empty() {
        return Err(("ERR_DESTINATION_UNCHECKED", "names no file once Windows drops its trailing dots and spaces"));
    }
    if bytes.contains(&b':') {
        return Err(("ERR_DESTINATION_STREAM", "names a data stream inside a file (the part after ':'), not a file"));
    }
    // SAFETY: only ASCII bytes were cut, from the end, so what is left ends where an
    // OsStr's encoded bytes may be split.
    Ok(unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(bytes) }.to_os_string())
}

/// Takes the native (shell-observed) hold on `canonical` for `window`, or
/// refuses because someone already has the file open. Read-ONLY opens do not
/// hold: several readers of one file cannot lose each other's work, and
/// refusing them would break the legitimate "inspect it while it is open
/// elsewhere" case.
///
/// A hold this window already has via its PAGE does not block it: a native
/// close followed immediately by a re-open in the same window would otherwise
/// race the push that releases the page half. A second NATIVE hold on one
/// file is still refused even within one window — the host dedupes in-page,
/// so reaching here means it did not.
pub(crate) fn claim_native(
    files: &OpenFiles,
    canonical: &Path,
    window: &str,
) -> Result<NativeHold, String> {
    claim_native_at(files, canonical, window, Instant::now())
}

fn claim_native_at(
    files: &OpenFiles,
    canonical: &Path,
    window: &str,
    now: Instant,
) -> Result<NativeHold, String> {
    let mut inner = files.0.lock().unwrap();
    inner.prune(now);
    match inner.holders.get_mut(canonical) {
        Some(holder) if holder.window != window => {
            return Err(already_open_error(canonical, &holder.window, window));
        }
        Some(holder) if holder.native => {
            return Err(already_open_error(canonical, &holder.window, window));
        }
        Some(holder) => holder.native = true,
        None => {
            inner.holders.insert(
                canonical.to_path_buf(),
                Holder {
                    window: window.to_string(),
                    native: true,
                    page: None,
                },
            );
        }
    }
    Ok(NativeHold {
        files: files.clone(),
        path: canonical.to_path_buf(),
        window: window.to_string(),
    })
}

/// The WASM lane's entry gate: refuses a read of a file another window
/// already has open, and otherwise takes the provisional hold that covers the
/// gap until that window's first push.
///
/// A file gone from its name yields `Ok(())` with no hold: the read it guards
/// fails on its own. One whose location cannot be resolved is refused by name
/// (`crate::resolved_for_guard`): it could not be held, so it is not read unguarded.
pub(crate) fn hold_for_read(
    files: &OpenFiles,
    requested: &Path,
    window: &str,
) -> Result<(), String> {
    let canonical = match crate::resolve_for_guard(requested) {
        crate::Resolved::Canonical(canonical) => canonical,
        crate::Resolved::Missing => return Ok(()),
        crate::Resolved::Unresolvable(sentence) => return Err(sentence),
    };
    hold_for_read_at(files, &canonical, window, Instant::now())
}

fn hold_for_read_at(
    files: &OpenFiles,
    canonical: &Path,
    window: &str,
    now: Instant,
) -> Result<(), String> {
    let mut inner = files.0.lock().unwrap();
    inner.prune(now);
    match inner.holders.get_mut(canonical) {
        Some(holder) if holder.window != window => {
            Err(already_open_error(canonical, &holder.window, window))
        }
        // Never DOWNGRADE a confirmed hold to an expiring one: a refresh
        // re-reads a file the page has had open for hours, and turning that
        // into a provisional hold would release it a minute later.
        Some(holder) => {
            if holder.page != Some(PageHold::Reported) {
                holder.page = Some(PageHold::Provisional(now + PROVISIONAL_HOLD_TTL));
            }
            Ok(())
        }
        None => {
            inner.holders.insert(
                canonical.to_path_buf(),
                Holder {
                    window: window.to_string(),
                    native: false,
                    page: Some(PageHold::Provisional(now + PROVISIONAL_HOLD_TTL)),
                },
            );
            Ok(())
        }
    }
}

/// The WebAssembly read's gate, in the order its refusals must reach the user. A file
/// another window has open is named as that first: when that window holds it natively,
/// its own sidecar is what keeps the log beside the file, so "a -wal file holding
/// frames" would send the user to close a program that is SQLite Explorer itself. That
/// look claims nothing. Then a log beside the file, and only then the hold, so a read
/// refused for a log claims nothing another window would then wait out.
pub(crate) fn admit_wasm_read(files: &OpenFiles, requested: &Path, window: &str) -> Result<(), String> {
    refuse_if_open_elsewhere(files, requested, window)?;
    if let Some(refusal) = crate::snapshot_refusal(requested) {
        return Err(refusal);
    }
    hold_for_read(files, requested, window)
}

/// `hold_for_read`'s refusal without its hold. The path is resolved before the lock is
/// taken and the lock is released before anything is stat-ed: `set_unsaved_state`
/// takes it on the main thread. Like `hold_for_read`, a file gone from its name adds
/// no refusal (the read it guards fails on its own), and one whose location cannot be
/// resolved is refused by name.
fn refuse_if_open_elsewhere(files: &OpenFiles, requested: &Path, window: &str) -> Result<(), String> {
    let canonical = match crate::resolve_for_guard(requested) {
        crate::Resolved::Canonical(canonical) => canonical,
        crate::Resolved::Missing => return Ok(()),
        crate::Resolved::Unresolvable(sentence) => return Err(sentence),
    };
    refuse_if_open_elsewhere_at(files, &canonical, window, Instant::now())
}

fn refuse_if_open_elsewhere_at(
    files: &OpenFiles,
    canonical: &Path,
    window: &str,
    now: Instant,
) -> Result<(), String> {
    let inner = files.0.lock().unwrap();
    match inner.holders.get(canonical) {
        // An expired provisional hold refuses nothing, pruned or not.
        Some(holder) if holder.window != window && holder.live_at(now) => {
            Err(already_open_error(canonical, &holder.window, window))
        }
        _ => Ok(()),
    }
}

/// Installs `window`'s reported open-path set WHOLESALE, replacing whatever
/// it reported before. This is what makes a close release itself: a database
/// the page no longer lists is simply not in the new set.
///
/// Never touches an entry owned by another window — neither to take it (a
/// page must not be able to squat on a file someone else has open) nor to
/// release it. Never touches the `native` flag either, in either direction.
///
/// Returns what was installed, or `Err` for a push that was rejected whole (see
/// `MAX_REPORTED_OPEN_PATHS`).
pub(crate) fn sync_reported(
    files: &OpenFiles,
    window: &str,
    spellings: &[PathBuf],
) -> Result<Synced, String> {
    sync_reported_at(files, window, spellings, Instant::now())
}

/// What a push installed: how many spellings, and the ones whose location could not
/// be resolved, with the sentence the user is told (`crate::resolved_for_guard`).
#[derive(Debug)]
pub(crate) struct Synced {
    /// Read by the tests, which measure a push by it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) installed: usize,
    pub(crate) unresolvable: Vec<(PathBuf, String)>,
}

fn sync_reported_at(
    files: &OpenFiles,
    window: &str,
    spellings: &[PathBuf],
    now: Instant,
) -> Result<Synced, String> {
    let mut unresolvable: Vec<(PathBuf, String)> = Vec::new();
    if spellings.len() > MAX_REPORTED_OPEN_PATHS {
        return Err(format!(
            "a window reported {} open databases, over the {MAX_REPORTED_OPEN_PATHS} cap; \
             keeping its previous set rather than releasing holds it may still need",
            spellings.len()
        ));
    }
    let mut inner = files.0.lock().unwrap();
    inner.prune(now);
    // Resolve through the previous push's spellings first, so a steady state
    // costs no `realpath` at all. A spelling gone from its name is dropped: it
    // names no file, so it can collide with nothing. One whose location cannot be
    // resolved is dropped too, since it cannot be keyed, and handed back so the
    // user is told that file is not guarded.
    let previous = inner.reported.remove(window).unwrap_or_default();
    let mut current: HashMap<PathBuf, PathBuf> = HashMap::with_capacity(spellings.len());
    for spelling in spellings {
        let canonical = match previous.get(spelling) {
            Some(cached) => cached.clone(),
            None => match crate::resolve_for_guard(spelling) {
                crate::Resolved::Canonical(canonical) => canonical,
                crate::Resolved::Missing => continue,
                crate::Resolved::Unresolvable(sentence) => {
                    unresolvable.push((spelling.clone(), sentence));
                    continue;
                }
            },
        };
        current.insert(spelling.clone(), canonical);
    }
    let claimed: HashSet<PathBuf> = current.values().cloned().collect();

    // Confirm what this window still lists, release what it dropped.
    inner.holders.retain(|path, holder| {
        if holder.window != window {
            return true;
        }
        if claimed.contains(path) {
            holder.page = Some(PageHold::Reported);
            return true;
        }
        holder.page = None;
        holder.native
    });
    // …and take the ones it lists but does not hold yet.
    for path in claimed {
        match inner.holders.entry(path) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                if entry.get().window != window {
                    // Either a genuine race (the other window opened it first
                    // and this push was already in flight) or a page naming a
                    // file it does not have. Both resolve the same way: the
                    // open was refused, so there is nothing to hold.
                    eprintln!(
                        "[open-files] {window} reported {} as open but {} holds it; ignoring",
                        entry.key().display(),
                        entry.get().window
                    );
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Holder {
                    window: window.to_string(),
                    native: false,
                    page: Some(PageHold::Reported),
                });
            }
        }
    }
    let installed = current.len();
    inner.reported.insert(window.to_string(), current);
    Ok(Synced { installed, unresolvable })
}

/// Drops every PAGE hold a window has, leaving its native holds alone.
///
/// Called on `PageLoadEvent::Started`: the reloading page's registry is gone
/// with the document, so nothing it reported is true any more. Its sidecars
/// are still live processes at that instant — they are reaped detachedly —
/// so their holds stay until those guards drop.
pub(crate) fn clear_page_holds(files: &OpenFiles, window: &str) {
    let mut inner = files.0.lock().unwrap();
    inner.reported.remove(window);
    inner.holders.retain(|_, holder| {
        if holder.window != window {
            return true;
        }
        holder.page = None;
        holder.native
    });
}

/// Drops EVERYTHING a window holds, native flag included.
///
/// Called when the window is destroyed, which is the answer to "a window that
/// dies without a final push must not strand a hold". It runs eagerly rather
/// than waiting for the detached reaper to drop the sidecar handles, so the
/// file is reopenable the instant the window is gone; the reaper's later drop
/// is a no-op because `NativeHold::drop` checks the window label first.
pub(crate) fn forget_window_holds(files: &OpenFiles, window: &str) {
    let mut inner = files.0.lock().unwrap();
    inner.reported.remove(window);
    inner.holders.retain(|_, holder| holder.window != window);
}

/// Which window, if any, currently has the file `requested` names open.
/// Read-only; used by tests and by diagnostics.
#[cfg(test)]
pub(crate) fn holder_of(files: &OpenFiles, requested: &Path) -> Option<String> {
    let canonical = fs::canonicalize(requested).ok()?;
    let inner = files.0.lock().unwrap();
    inner.owner(&canonical, Instant::now()).map(str::to_string)
}

/// The refusal a duplicate open raises. Both entry points reach it through
/// `claim_native`/`hold_for_read`; this is the seam that lets a test assert on
/// the exact sentence the user reads.
#[cfg(test)]
pub(crate) fn refuse_second_opener(path: &Path, owner: &str, here: &str) -> String {
    already_open_error(path, owner, here)
}

/// Opaque, shell-issued handle for one open native database. It is a bare
/// counter token (`db_<n>`) and NEVER a path: paths are user data, they are
/// not unique per open (the same file may legitimately be opened twice), and
/// a path-shaped key invites the webview to construct one. The webview
/// receives an id from `native_open` and echoes it back on every later call.
pub(crate) type DbId = String;

/// Process-monotonic source of `DbId`s. Deliberately process-global rather
/// than per-registry: the registry is split per window, and ids that
/// stay unique across every registry mean a leaked or stale id can never
/// resolve in a DIFFERENT window's registry. Uniqueness is the requirement,
/// not unpredictability — the id is an authorisation *reference*, not a
/// capability: it only ever names a sidecar the shell already bound to an
/// allowlisted path, and guessing one buys no access the same page could not
/// get by opening that database itself.
static DB_SEQ: AtomicU64 = AtomicU64::new(0);

pub(crate) fn next_db_id() -> DbId {
    format!("db_{}", DB_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// Ceiling on simultaneously open native databases, **per window**. The old
/// replace-the-one-sidecar semantics bounded process count implicitly; the registry removes
/// that bound, and `native_open` is webview-reachable for any path ALREADY on
/// the session allowlist — so a compromised page could re-open the same
/// innocent file in a loop and spawn processes until the machine gives up.
///
/// The number is derived from the outbound memory bound, not picked for
/// roundness: worst-case buffered outbound bytes are
/// `WRITE_QUEUE_CAP × MAX_FRAME_BYTES × MAX_NATIVE_SIDECARS` =
/// 4 × 16 MiB × 16 = **1 GiB**, and that ceiling is REACHABLE from a
/// compromised page (open N sidecars on one allowlisted file, wedge each with
/// a long query so it stops draining stdin, then push four cap-sized frames
/// at each). 16 keeps that bound at a gigabyte while staying far above any
/// plausible number of database tabs a human opens; 32 would have doubled it
/// for no practical gain. Exit cost does not enter into it — `shutdown_all`
/// fans the reaps out, so quitting costs ~one grace period at any N.
///
/// Native transfers leave this bound as it is: every piece is one frame of at
/// most MAX_FRAME_BYTES. Their memory is inside each sidecar process, one
/// transfer per connection of at most MAX_TRANSFER_UNITS (2^28) UTF-16 units of
/// JSON text, freed on commit, on the first frame that does not continue it, and
/// at exit. Holding the text is the small part (512 MiB as two-byte JS strings,
/// derived); decoding it is not. The review measured tjs at about 45 bytes per
/// character of object-dense JSON after JSON.parse, and about 93 with the decode's
/// copy (synthetic `[[],[],…]` text, not a real payload): about 11 to 23 GiB for
/// one sidecar decoding a request at the 2^28-unit ceiling, against about 0.7 to
/// 1.4 GiB for one 16 MiB frame. Reaching it needs a compromised page, which can
/// push such a request to every sidecar it opens and then send the invoke that
/// decodes it: local memory exhaustion of the sidecars and the machine, with no
/// file read or written. The shell's own 1 GiB buffering bound above is
/// unchanged; the shell does not bound sidecar memory, which a page could already
/// grow with SQL alone.
///
/// PER WINDOW, not app-wide. Two reasons, in order:
///   1. The host's own `MAX_OPEN_DATABASES = 16` is per registry, and a
///      registry is per window — so an app-wide shell cap would refuse an
///      open the page believes it has room for ("16 databases are already
///      open" in a window showing none), which is an unexplainable failure.
///      Two caps over the same resource must agree or one of them lies.
///   2. The bound the number is derived from stays intact per window, and
///      the MULTIPLIER (window count) is not attacker-controlled: windows
///      are created by the File ▸ Open in New Window menu item only. The
///      capability set grants the page neither `core:window:allow-create`
///      nor `core:webview:allow-create-webview-window` (neither is in
///      `core:window:default` / `core:webview:default`), and window creation
///      is a `plugin:`-prefixed core command, so unlike this app's own
///      commands it IS ACL-checked. A compromised page therefore cannot
///      multiply the bound; only a user opening N windows can, and each
///      window's page must be compromised to fill its own gigabyte.
pub(crate) const MAX_NATIVE_SIDECARS: usize = 16;

fn too_many_databases_error() -> String {
    format!(
        "ERR_NATIVE_TOO_MANY_DATABASES: {MAX_NATIVE_SIDECARS} native databases are already open; close one before opening another"
    )
}

fn shutting_down_error() -> String {
    "ERR_NATIVE_SHUTTING_DOWN: the shell is shutting down; no new native database can be opened"
        .to_string()
}

/// The registry's contents, behind ONE lock so the shutdown latch and the map
/// can never be observed out of step.
#[derive(Default)]
struct Registry {
    /// Open sidecars, keyed by the DbId the shell issued for each.
    sidecars: HashMap<DbId, SidecarHandle>,
    /// One-way latch, set by the terminal drain. `native_open` holds
    /// `open_serial` across a spawn + ≤10 s handshake, so an open that was
    /// already past the drain would otherwise insert a live child into the
    /// emptied map at app exit — a process holding the user's database with
    /// nothing left alive to reap it. Checked under this same lock at insert.
    shutting_down: bool,
}

/// The registry of open sidecars for ONE window: N entries, each keyed by the
/// DbId the shell issued for it. Kept as a plain value (not a hidden global)
/// precisely so one of these could sit behind every window label
/// without touching the routing code — `lib.rs`'s `Windows` map owns the
/// per-window instances, and every command resolves the one belonging to the
/// window that sent it (the label comes from Tauri's own webview identity,
/// never from an argument the page could choose).
///
/// `open_serial` serialises `native_open` bodies end to end. It no longer
/// guards a replace, but the capacity check and the insert straddle a spawn +
/// handshake, and two concurrent opens could otherwise both pass a check at
/// the cap boundary. It deliberately does NOT cover `native_rpc`, so one
/// database's slow open never serialises another's queries.
#[derive(Default)]
pub struct NativeSidecar {
    registry: Mutex<Registry>,
    open_serial: Mutex<()>,
}

fn shutdown_handle(handle: SidecarHandle, reason: &str) {
    // Dropping the queue sender is the graceful path: the writer thread
    // drains what is queued, then drops stdin, and the sidecar reads EOF and
    // exits 0 on its own (also its documented orphan path). Nothing here
    // ever waits on the writer: if it is wedged in a `write_all` against a
    // child that stopped reading, the grace period below expires and the
    // SIGKILL collapses the pipe (EPIPE), which is what unblocks the writer
    // — so this function is bounded (~grace + reap) regardless of writer
    // state, including when it runs on the main thread at app exit. Fanout
    // FIRST is deliberate — pending requests get their structured error
    // immediately instead of waiting out the reap.
    *handle.core.writer_tx.lock().unwrap() = None;
    handle.core.fail_all(reason);
    let status = wait_or_kill(&handle.child, SHUTDOWN_WAIT, false);
    eprintln!("[native] sidecar shut down: {status}");
}

/// Path-authority layer 1, plus the canonical binding the sidecar's layer 2
/// compares against. Order matters:
///
/// 1. The EXACT requested path must already be session-allowlisted — the set
///    only dialog picks and OS-delivered opens feed (`assert_allowlisted`,
///    the same gate `read_database_bytes` uses). The webview can never
///    introduce a new path here.
/// 2. The path is canonicalised for the argv binding (layer 2's
///    contract: "the shell canonicalises; the sidecar does not normalise").
/// 3. The FINAL component must not be a symlink: an rw sidecar session
///    writes through the real file, and the shell's own save path
///    (`write_atomically`'s rename) never follows a final-component symlink
///    — this check preserves that invariant for the native engine. Checked
///    by comparing full canonicalisation against canonical-parent + name
///    (directory-level symlinks like /tmp → /private/tmp still resolve).
///    NOTE: still TOCTOU-racy against a swap between this check and the
///    sidecar's open — that residue is the deferred F3 symlink-race cluster
///    (see lib.rs), not newly introduced here; this closes the pre-planted
///    variant the way `File::create_new` does for saves.
pub(crate) fn resolve_bound_path(
    allowlist: &crate::SessionAllowlist,
    requested: &Path,
) -> Result<PathBuf, String> {
    crate::assert_allowlisted(allowlist, requested)
        .map_err(|e| format!("ERR_NATIVE_PATH_NOT_ALLOWED: {e}"))?;
    let full = fs::canonicalize(requested).map_err(|e| {
        format!(
            "ERR_NATIVE_PATH_NOT_ALLOWED: cannot resolve {}: {e}",
            requested.display()
        )
    })?;
    let parent = requested
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or("ERR_NATIVE_PATH_NOT_ALLOWED: path has no parent directory")?;
    let name = requested
        .file_name()
        .ok_or("ERR_NATIVE_PATH_NOT_ALLOWED: path has no file name")?;
    let via_parent = fs::canonicalize(parent)
        .map_err(|e| format!("ERR_NATIVE_PATH_NOT_ALLOWED: cannot resolve parent: {e}"))?
        .join(name);
    if via_parent != full {
        return Err(
            "ERR_NATIVE_PATH_NOT_ALLOWED: the final path component is a symlink; refusing to bind the native engine through it"
                .into(),
        );
    }
    Ok(full)
}

/// What `native_open` hands back to the webview: the routing token plus the
/// canonical path the sidecar is bound to (which the host must echo verbatim
/// in its `initializeDatabase` config.path, or layer 3 refuses it).
#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenedDatabase {
    pub(crate) db_id: DbId,
    pub(crate) bound_path: String,
}

/// Refuses at the open cap (or once the registry is latched shut). Checked
/// BEFORE the spawn so a refusal never leaves a child to reap;
/// `register_sidecar` re-checks both conditions under the lock.
fn assert_capacity(manager: &NativeSidecar) -> Result<(), String> {
    let registry = manager.registry.lock().unwrap();
    if registry.shutting_down {
        return Err(shutting_down_error());
    }
    if registry.sidecars.len() >= MAX_NATIVE_SIDECARS {
        return Err(too_many_databases_error());
    }
    Ok(())
}

/// Adds a launched sidecar to the registry under a freshly issued DbId. A
/// refused registration — at the cap, or after the registry latched shut —
/// SHUTS THE HANDLE DOWN rather than dropping it: a dropped handle would
/// leave a live child holding the user's database with nothing left able to
/// kill it. Both conditions are re-checked here, under the same lock the
/// terminal drain takes, because `open_inner`'s pre-flight check happens
/// before a spawn + ≤10 s handshake and can go stale in either direction.
fn register_sidecar(manager: &NativeSidecar, handle: SidecarHandle) -> Result<DbId, String> {
    let db_id = next_db_id();
    let refusal = {
        let mut registry = manager.registry.lock().unwrap();
        if registry.shutting_down {
            shutting_down_error()
        } else if registry.sidecars.len() >= MAX_NATIVE_SIDECARS {
            too_many_databases_error()
        } else {
            registry.sidecars.insert(db_id.clone(), handle);
            return Ok(db_id);
        }
        // Never shut a handle down under the registry lock: shutdown_handle
        // waits out a grace period, and every other command needs this lock.
    };
    shutdown_handle(handle, &refusal);
    Err(refusal)
}

/// Test-only registry seams. They live out here rather than in this module's
/// `tests` child because the cross-WINDOW tests are in `lib.rs`, which owns
/// the per-window map and cannot reach a sibling module's private items.
/// Never compiled into a build the webview can reach.
#[cfg(test)]
pub(crate) fn open_ids(manager: &NativeSidecar) -> std::collections::HashSet<DbId> {
    manager.registry.lock().unwrap().sidecars.keys().cloned().collect()
}

/// Whether an id resolves in THIS registry. Exists so a cross-window test can
/// assert the refusal FAST: a resolver that retargeted would make the `rpc`
/// that follows block on a response nobody will ever send, turning a clean
/// failure into a wedged suite.
#[cfg(test)]
pub(crate) fn resolves(manager: &NativeSidecar, db_id: &str) -> bool {
    core_for(manager, db_id).is_ok()
}

/// One test-owned registry entry: its id, its core, and the writer queue the
/// TEST drains in the sidecar's place.
#[cfg(test)]
pub(crate) type FakeEntry = (DbId, Arc<SidecarCore>, mpsc::Receiver<Vec<u8>>);

/// A registry entry whose writer queue the TEST drains, so every assertion
/// can name exactly which sidecar an envelope reached (or prove one received
/// nothing at all). The child is a placeholder that has already exited —
/// process lifecycle is exercised by the close/exit tests and by the live
/// two-sidecar e2e.
#[cfg(test)]
pub(crate) fn try_fake_entry(manager: &NativeSidecar, bound: &str) -> Result<FakeEntry, String> {
    try_fake_entry_claimed(manager, bound, None)
}

/// `try_fake_entry` with an app-global native hold attached, so a test can
/// prove the hold is released by whichever registry path removes the handle.
#[cfg(test)]
pub(crate) fn try_fake_entry_claimed(
    manager: &NativeSidecar,
    bound: &str,
    native_hold: Option<NativeHold>,
) -> Result<FakeEntry, String> {
    try_fake_entry_with(manager, bound, native_hold, None)
}

/// `try_fake_entry` PINNED to a real file's identity, so the replacement gate
/// can be exercised against a bound path that exists on disk.
#[cfg(test)]
pub(crate) fn try_fake_entry_pinned(
    manager: &NativeSidecar,
    bound: &str,
    identity: FileIdentity,
) -> Result<FakeEntry, String> {
    try_fake_entry_with(manager, bound, None, Some(identity))
}

#[cfg(test)]
fn placeholder_child() -> std::process::Child {
    #[cfg(unix)]
    let mut command = Command::new("/usr/bin/true");
    #[cfg(windows)]
    let mut command = {
        let mut command = Command::new("cmd.exe");
        command.args(["/d", "/c", "exit", "0"]);
        command
    };
    command.spawn().expect("spawn a placeholder child")
}

#[cfg(test)]
fn try_fake_entry_with(
    manager: &NativeSidecar,
    bound: &str,
    native_hold: Option<NativeHold>,
    identity: Option<FileIdentity>,
) -> Result<FakeEntry, String> {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE_CAP);
    let core = Arc::new(SidecarCore::new(bound.to_string(), identity, tx));
    let child = placeholder_child();
    let id = register_sidecar(
        manager,
        SidecarHandle {
            core: Arc::clone(&core),
            child: Arc::new(Mutex::new(child)),
            _native_hold: native_hold,
        },
    )?;
    Ok((id, core, rx))
}

#[cfg(test)]
pub(crate) fn fake_entry(manager: &NativeSidecar, bound: &str) -> FakeEntry {
    try_fake_entry(manager, bound).expect("register")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn open_inner(
    app: &AppHandle,
    allowlist: &crate::SessionAllowlist,
    files: &OpenFiles,
    manager: &NativeSidecar,
    window: &str,
    path: &str,
    read_only: bool,
    max_bytes: Option<u64>,
) -> Result<OpenedDatabase, String> {
    let _serial = manager.open_serial.lock().unwrap();
    let bound = resolve_bound_path(allowlist, Path::new(path))?; // LAYER 1
    let bound_str = bound
        .to_str()
        .ok_or("ERR_NATIVE_PATH_NOT_ALLOWED: non-UTF-8 paths cannot cross the JSON transport")?
        .to_string();
    // The configured maxFileSize refusal and the identity pin, from one stat,
    // before anything is claimed or spawned (see `admit_file`).
    let identity = admit_file(&bound, max_bytes)?;
    // Before the spawn, and app-globally: two windows editing one file is
    // silent data loss (see `OpenFiles`). `open_serial` only serialises opens
    // WITHIN a window, so this is where cross-window opens are ordered. The
    // hold is released by `Drop` if anything below fails.
    let native_hold = if read_only {
        None
    } else {
        Some(claim_native(files, &bound, window)?)
    };
    assert_capacity(manager)?;
    let paths = locate_native_dir(&native_dir_candidates(app))
        .ok_or("ERR_NATIVE_UNAVAILABLE: native engine artifacts are not present in this build")?;
    // ADD semantics: every open is its own sidecar, argv-bound to its own
    // path, reachable only through its own DbId. Existing sidecars are left
    // alone — closing one is `native_close`'s job, and nothing else may
    // silently take a database away from the page that opened it. The entry
    // appears only after the handshake passed, so an id is never handed out
    // for a sidecar that is not answering.
    let (core, child) = launch_sidecar(&paths, &bound_str, read_only, Some(identity))?;
    let db_id = register_sidecar(
        manager,
        SidecarHandle {
            core,
            child,
            _native_hold: native_hold,
        },
    )?;
    Ok(OpenedDatabase {
        db_id,
        bound_path: bound_str,
    })
}

/// THE routing authority: resolves a webview-supplied DbId to its sidecar,
/// by exact match and nothing else. Unknown, already-closed, and malformed
/// ids collapse to ONE refusal — deliberately indistinguishable, so the
/// webview learns nothing from the difference — and no branch here can ever
/// fall back to another sidecar. The id is echoed back (bounded) for
/// diagnosis; it is webview-controlled text, so it is excerpted like every
/// other hostile string this module logs.
fn core_for(manager: &NativeSidecar, db_id: &str) -> Result<Arc<SidecarCore>, String> {
    manager
        .registry
        .lock()
        .unwrap()
        .sidecars
        .get(db_id)
        .map(|handle| Arc::clone(&handle.core))
        .ok_or_else(|| unknown_db_error(db_id))
}

/// ONE refusal for every id that does not resolve, so resolution failures
/// cannot be told apart by the caller. Shared by the rpc/export resolver and
/// by `close_inner` for the same reason.
fn unknown_db_error(db_id: &str) -> String {
    format!(
        "ERR_NATIVE_UNKNOWN_DB: no open native database has id {:?}",
        excerpt(db_id)
    )
}

/// THE authority half of an rpc, shared by both waiters below so neither can
/// drift from the other: resolve the sidecar BY ID (never by envelope
/// content), then run layer 3 against THAT sidecar's binding. Everything
/// after this point is only about how the answer is waited for.
fn rpc_prepare(
    manager: &NativeSidecar,
    db_id: &str,
    envelope: &str,
) -> Result<(Arc<SidecarCore>, MessageKey), String> {
    let core = core_for(manager, db_id)?; // ROUTING (by id, never by content)
    let key = gate_envelope(envelope, &core.bound_path)?; // LAYER 3, per sidecar
    assert_file_current(&core)?; // the file is still the one this sidecar opened
    Ok((core, key))
}

/// The production `native_rpc` body.
///
/// `.await`s the answer instead of blocking on it. That is not a style
/// choice: command bodies run on tauri's shared multi-thread tokio runtime
/// (`respond_async_serialized` → `async_runtime::spawn`), whose worker count
/// is `available_parallelism()` — 12 on the development machine, i.e. FEWER
/// than `MAX_NATIVE_SIDECARS` (16) in a single window. A blocking wait here
/// occupied one shared worker for the whole query, so a dozen concurrent slow
/// queries froze every command in every window (open, save, close, both
/// exports) with nothing to time them out. Awaiting a oneshot parks no thread
/// at all.
///
/// Hang-freedom still comes primarily from `fail_all` — every sidecar death
/// resolves every pending request — with `RPC_TIMEOUT` as the shell's own
/// backstop for a sidecar that neither answers nor dies.
async fn rpc_awaited(
    manager: &NativeSidecar,
    db_id: &str,
    envelope: &str,
) -> Result<String, String> {
    let (core, key) = rpc_prepare(manager, db_id, envelope)?;
    let rx = core.submit_awaited(key.clone(), envelope)?;
    match tokio::time::timeout(RPC_TIMEOUT, rx).await {
        // Post-check: a replacement that landed DURING the statement makes the
        // refusal the actionable answer, whatever the sidecar said.
        Ok(Ok(outcome)) => {
            assert_file_current(&core)?;
            outcome
        }
        // The responder was dropped without answering. Unreachable today —
        // every removal path responds before dropping — kept distinct so a
        // future removal-without-send surfaces as itself.
        Ok(Err(_)) => {
            Err("ERR_NATIVE_SIDECAR_EXITED: the sidecar closed before answering".into())
        }
        Err(_elapsed) => {
            core.cancel(&key);
            Err(format!(
                "ERR_NATIVE_RPC_TIMEOUT: the sidecar did not answer within {}s; the request was abandoned",
                RPC_TIMEOUT.as_secs()
            ))
        }
    }
}

/// The blocking sibling of `rpc_awaited`, kept for the suite: the tests drive
/// rpc synchronously (they answer from a plain thread standing in for the
/// sidecar), and both paths share `rpc_prepare` + `submit_with`, so the whole
/// authority — id routing, layer 3, the pending-map registration ordering — is
/// exactly the code production runs. Only the wait differs, and the wait has
/// its own tests.
#[cfg(test)]
pub(crate) fn rpc_inner(
    manager: &NativeSidecar,
    db_id: &str,
    envelope: &str,
) -> Result<String, String> {
    let (core, key) = rpc_prepare(manager, db_id, envelope)?;
    let rx = core.submit(key, envelope)?;
    match rx.recv() {
        Ok(outcome) => {
            assert_file_current(&core)?; // same post-check as the awaited path
            outcome
        }
        Err(_) => Err("ERR_NATIVE_SIDECAR_EXITED: the sidecar closed before answering".into()),
    }
}

/// Closes exactly the named database. Unlike the old single-slot close this
/// is NOT a silent no-op when the id is unknown: with N sidecars, "close
/// whatever" is precisely the ambiguity the DbId exists to remove, and a
/// close that quietly did nothing would hide a host-side bug (or a
/// double-close racing a crash) instead of surfacing it.
pub(crate) fn close_inner(
    manager: &NativeSidecar,
    db_id: &str,
    reason: &str,
) -> Result<(), String> {
    // Take the handle OUT of the lock first: shutdown_handle waits out a
    // grace period and must never hold the registry against other commands.
    let handle = manager.registry.lock().unwrap().sidecars.remove(db_id);
    match handle {
        Some(handle) => {
            shutdown_handle(handle, reason);
            Ok(())
        }
        None => Err(unknown_db_error(db_id)),
    }
}

/// Empties the registry and hands back what was in it. `latch_shut` sets the
/// one-way shutdown flag in the SAME critical section, so no open can slip a
/// live child into the map behind a terminal drain.
fn drain_registry(manager: &NativeSidecar, latch_shut: bool) -> Vec<SidecarHandle> {
    let mut registry = manager.registry.lock().unwrap();
    if latch_shut {
        registry.shutting_down = true;
    }
    registry.sidecars.drain().map(|(_id, handle)| handle).collect()
}

/// Shuts a batch of handles down CONCURRENTLY — a thread each, then join.
/// Serially this is N grace periods: every `wait_or_kill` waits its own
/// `SHUTDOWN_WAIT` before the SIGKILL, so a quit with wedged children would
/// freeze for N × 2 s (half a minute at the cap). Fanned out, the aggregate
/// is ~one grace period at any N, and each sidecar keeps the identical
/// per-sidecar discipline (fanout first, bounded grace, force-kill, reap).
/// A panicking reaper is logged and never propagated: at exit, the remaining
/// joins matter more than the panic.
fn shutdown_all(handles: Vec<SidecarHandle>, reason: &str) {
    let reapers: Vec<_> = handles
        .into_iter()
        .map(|handle| {
            let reason = reason.to_string();
            std::thread::spawn(move || shutdown_handle(handle, &reason))
        })
        .collect();
    for reaper in reapers {
        if let Err(e) = reaper.join() {
            eprintln!("[native] a sidecar shutdown thread panicked: {e:?}");
        }
    }
}

/// TERMINAL close-all for ONE registry — the single-window shorthand for
/// `close_all_registries`, kept because most tests have exactly one. The latch
/// is one-way, so a manager that has been through here never accepts another
/// open. Test-only: the shell itself always closes every window's registry in
/// one batch, so this must not become a second production shutdown path.
#[cfg(test)]
pub(crate) fn close_all_inner(manager: &NativeSidecar, reason: &str) {
    close_all_registries(&[manager], reason);
}

/// The APP-EXIT path with multiple windows: drains and latches EVERY window's
/// registry, then reaps the whole lot in ONE parallel batch. Batching across
/// windows (rather than calling `close_all_inner` per window) is what keeps
/// the aggregate quit cost at ~one grace period no matter how many windows
/// are open — serialising per window would reintroduce, at window
/// granularity, exactly the N × SHUTDOWN_WAIT freeze that `shutdown_all`
/// exists to prevent within one.
pub(crate) fn close_all_registries(managers: &[&NativeSidecar], reason: &str) {
    let handles: Vec<SidecarHandle> = managers
        .iter()
        .flat_map(|manager| drain_registry(manager, true))
        .collect();
    shutdown_all(handles, reason);
}

/// Closes one WINDOW's databases, and only that window's: the window is gone
/// for good, so the registry is latched shut (unlike a page reload, which
/// leaves it usable for the next page). Same drain-synchronously /
/// reap-detached split as `reap_orphaned_sidecars` and for the same reason —
/// this runs on the main thread from the window-destroyed handler, where a
/// wedged child must not freeze the UI for a grace period. The returned
/// handle is tracked by the caller and joined at exit, so a quit immediately
/// after a window close still waits the reaps out.
pub(crate) fn close_window_registry(
    manager: &NativeSidecar,
    reason: &str,
) -> Option<std::thread::JoinHandle<()>> {
    // Latches even when the drain comes back empty: an open still inside its
    // ≤10 s handshake when the window went away must be refused, not inserted
    // into the registry of a window that no longer exists.
    let handles = drain_registry(manager, true);
    if handles.is_empty() {
        return None;
    }
    eprintln!(
        "[native] window closed with {} native database(s) still open; closing them",
        handles.len()
    );
    detach_shutdown(handles, reason)
}

/// Reaps a drained batch off the main thread. Callers own the handle.
fn detach_shutdown(
    handles: Vec<SidecarHandle>,
    reason: &str,
) -> Option<std::thread::JoinHandle<()>> {
    let reason = reason.to_string();
    Some(std::thread::spawn(move || shutdown_all(handles, &reason)))
}

/// Reaps sidecars ORPHANED by a page-generation change (reload, devtools
/// reload, a navigation, a webview content-process restart) IN ONE WINDOW.
/// The manager handed in is the reloading window's own registry and nothing
/// else: with a second window open, reaping app-wide here would kill the
/// other window's live databases underneath the user on its first page load.
/// Every DbId lives in the page's JS heap, so a new page cannot name — or
/// close — anything the old one opened, while each stranded sidecar stays a
/// live `tjs` process
/// holding an rw connection to the user's database for the rest of the app's
/// life, invisible to the UI and counting against the open cap. Before the
/// registry existed, `native_open`'s replace semantics reaped the orphan on
/// the next open; nothing else does now, so the shell reaps here, at the one
/// moment it knows the old page is gone.
///
/// The drain is SYNCHRONOUS (the registry is empty the instant the new page
/// starts, so nothing can address a stale sidecar) while the reaping runs on
/// a detached thread: this is called from the webview's page-load callback on
/// the main thread, and a wedged child must not stall a reload for a grace
/// period. The returned handle is for tests; the call site drops it
/// deliberately. If the process exits before a detached reaper finishes, the
/// children are covered by their own orphan paths (stdin EOF when the shell's
/// fds close, then the ppid watchdog).
pub(crate) fn reap_orphaned_sidecars(
    manager: &NativeSidecar,
    reason: &str,
) -> Option<std::thread::JoinHandle<()>> {
    let handles = drain_registry(manager, false);
    if handles.is_empty() {
        return None; // The overwhelmingly common case: first load.
    }
    eprintln!(
        "[native] page reloaded with {} native database(s) still open; reaping the orphaned sidecar(s)",
        handles.len()
    );
    detach_shutdown(handles, reason)
}

// ---------------------------------------------------------------------------
// Shell-originated export route (out-of-band large exports)
// ---------------------------------------------------------------------------

/// Exclusive mkdir at the exact path, mode 0700. mkdir(2) EEXISTs on ANY
/// pre-existing entry — file, directory, or symlink, dangling included — and
/// never follows a final-component symlink, so a planted occupant fails
/// closed the way `File::create_new` does for saves. The 0700 dir, not any
/// property of the target file inside it, is the export route's security
/// boundary: VACUUM INTO refuses only a NON-EMPTY existing target (not a
/// fail-closed guard — a planted zero-byte file would be written into and a
/// symlink followed), so the target must live where nothing can be planted.
fn create_export_temp_dir_at(dir: &Path) -> Result<(), String> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder.create(dir).map_err(|e| {
        format!(
            "ERR_NATIVE_EXPORT_FAILED: could not create the export temp directory {}: {e}",
            dir.display()
        )
    })?;
    // mkdir's mode is masked by the umask; pin 0700 exactly on the directory
    // we just exclusively created. A failure removes it — no junk left.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir(dir);
            return Err(format!(
                "ERR_NATIVE_EXPORT_FAILED: could not restrict the export temp directory: {e}"
            ));
        }
    }
    Ok(())
}

/// Fresh shell-owned 0700 temp directory inside `parent` (dest's parent, so
/// the final rename stays on one filesystem and is atomic).
fn create_export_temp_dir(parent: &Path) -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let dir = parent.join(format!(
        ".sqlite-export-{}-{}-{}",
        std::process::id(),
        EXPORT_SEQ.fetch_add(1, Ordering::Relaxed),
        nanos
    ));
    create_export_temp_dir_at(&dir)?;
    Ok(dir)
}

/// Brief pause before `TempDirCleanup`'s single retry — long enough for an
/// in-flight sidecar write to land, short enough to stay imperceptible on the
/// rare timeout-race path (this is the only place it is ever waited).
const TEMP_CLEANUP_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Removes the export temp directory (and contents) when dropped, so every
/// exit from the export flow — success (the export was renamed out, the dir
/// is empty), failure, timeout, panic — cleans up exactly once. Removal
/// failure is logged, never panicked, in a Drop.
struct TempDirCleanup(PathBuf);

impl Drop for TempDirCleanup {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.0) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => {
                // EXPORT_TIMEOUT race: the sidecar is not killed on timeout, so
                // it can still be mid-write (a VACUUM journal, the chunk
                // target) and drop a fresh file into the dir between
                // remove_dir_all's readdir and its final rmdir → ENOTEMPTY,
                // leaving the 0700 dir orphaned next to dest. One brief pause
                // lets the in-flight write settle, then a single retry clears
                // it. Still best-effort: a persistent failure logs and leaks
                // (shell-owned 0700 dir, dest untouched — non-security).
                std::thread::sleep(TEMP_CLEANUP_RETRY_DELAY);
                if let Err(e) = fs::remove_dir_all(&self.0) {
                    eprintln!(
                        "[native] could not remove the export temp dir {} (after one retry): {e}",
                        self.0.display()
                    );
                }
            }
            Err(e) => eprintln!(
                "[native] could not remove the export temp dir {}: {e}",
                self.0.display()
            ),
        }
    }
}

/// Frames one shell-originated export request through the existing writer +
/// pending map and awaits the sidecar's `export-result` with a bounded
/// timeout. Trust model: the envelope is SHELL-CONSTRUCTED (args is parsed
/// JSON embedded as a value — nothing is string-spliced), so it does not pass
/// `gate_envelope`; the reply routes back through `route_payload` by the
/// echoed messageId exactly like every webview response. Returns the
/// sidecar's reported bytesWritten.
fn export_via_sidecar(
    core: &SidecarCore,
    method: &str,
    temp_path: &str,
    args: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<u64, String> {
    let message_id = format!(
        "{SHELL_MESSAGE_ID_PREFIX}_export_{}",
        EXPORT_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let mut content = serde_json::json!({
        "kind": "export",
        "messageId": message_id,
        "method": method,
        "tempPath": temp_path,
    });
    if let Some(args) = args {
        content["args"] = args;
    }
    let envelope = serde_json::json!({ "channel": "shell", "content": content }).to_string();
    // The cap check the webview path gets from gate_envelope, which this
    // shell-trusted path bypasses: an over-cap frame reaching write_frame
    // would kill the writer thread and fan out the WHOLE session, so hostile
    // or huge export args must be refused here instead.
    if envelope.len() as u64 > MAX_FRAME_BYTES as u64 {
        return Err(format!(
            "ERR_NATIVE_FRAME_TOO_LARGE: export request envelope is {} bytes; the frame cap is {} bytes (inclusive)",
            envelope.len(),
            MAX_FRAME_BYTES
        ));
    }
    let key = MessageKey::Str(message_id.clone());
    let rx = core.submit(key.clone(), &envelope)?;
    let text = match rx.recv_timeout(timeout) {
        Ok(Ok(text)) => text,
        // Crash fanout resolved the wait with the sidecar's failure reason.
        Ok(Err(e)) => return Err(e),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // The drop-without-reply contract (unknown kind / stale bundle)
            // or a genuinely wedged export: unregister so the map cannot
            // leak; a late reply then routes nowhere and is logged.
            core.cancel(&key);
            return Err(format!(
                "ERR_NATIVE_EXPORT_TIMEOUT: the sidecar did not answer the {method} export within {}s",
                timeout.as_secs()
            ));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // Unreachable today: the sender lives only in the pending map and
            // every removal path (route_payload, fail_all) sends before it
            // drops, so a disconnect means the entry is already gone. Kept
            // distinct so a future removal-without-send surfaces as a channel
            // close instead of being misreported as a full-timeout wait.
            return Err(
                "ERR_NATIVE_SIDECAR_EXITED: the native sidecar channel closed before replying to the export".into(),
            );
        }
    };
    parse_export_result(&text)
}

/// Structural validation of the sidecar's export-result reply. Fail closed on
/// every malformed shape — version skew must surface loudly, not as a
/// mysteriously empty dest file.
fn parse_export_result(text: &str) -> Result<u64, String> {
    let malformed = |what: &str| {
        format!("ERR_NATIVE_EXPORT_FAILED: malformed export-result from the sidecar ({what})")
    };
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| malformed(&format!("not JSON: {e}")))?;
    let content = value
        .get("content")
        .and_then(|v| v.as_object())
        .ok_or_else(|| malformed("no content object"))?;
    if content.get("kind").and_then(|v| v.as_str()) != Some("export-result") {
        return Err(malformed("kind is not export-result"));
    }
    match content.get("success").and_then(|v| v.as_bool()) {
        Some(true) => content
            .get("bytesWritten")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| malformed("success without a bytesWritten count")),
        Some(false) => {
            let error = content.get("error");
            let field = |name: &str| {
                error
                    .and_then(|e| e.get(name))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            };
            let code = field("code");
            let code_suffix = if code.is_empty() {
                String::new()
            } else {
                format!(" [{code}]")
            };
            Err(format!(
                "ERR_NATIVE_EXPORT_FAILED: the sidecar export failed{code_suffix}: {}: {}",
                field("name"),
                field("message")
            ))
        }
        None => Err(malformed("success is not a boolean")),
    }
}

/// Everything after the dialog: shell-owned temp dir next to dest, sidecar
/// writes `<tempdir>/export`, cross-check the result, atomic rename into
/// dest, temp dir removed on every path. Returns dest's file name (savedAs).
pub(crate) fn export_to_dest(
    core: &SidecarCore,
    method: &str,
    args: Option<serde_json::Value>,
    dest: &Path,
    timeout: Duration,
) -> Result<String, String> {
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or("ERR_NATIVE_EXPORT_FAILED: the destination has no parent directory")?;
    let temp_dir = create_export_temp_dir(parent)?;
    let _cleanup = TempDirCleanup(temp_dir.clone());
    let target = temp_dir.join("export");
    let target_str = target
        .to_str()
        .ok_or("ERR_NATIVE_EXPORT_FAILED: the destination directory's path is not valid UTF-8, so it cannot cross the JSON transport")?;

    let bytes_written = export_via_sidecar(core, method, target_str, args, timeout)?;

    // Cross-check the reply against what actually landed inside the shell's
    // own directory before publishing anything to dest: the file must exist,
    // be a REGULAR file (symlink_metadata — a symlink here would mean the
    // boundary failed; never follow it), and match the reported size.
    let meta = fs::symlink_metadata(&target).map_err(|e| {
        format!("ERR_NATIVE_EXPORT_FAILED: the sidecar reported success but no export file exists: {e}")
    })?;
    if !meta.file_type().is_file() || meta.len() != bytes_written {
        return Err(format!(
            "ERR_NATIVE_EXPORT_FAILED: the export on disk does not match the sidecar's report \
             (regular file: {}, {} bytes on disk vs {} reported)",
            meta.file_type().is_file(),
            meta.len(),
            bytes_written
        ));
    }

    crate::move_atomically(&target, dest).map_err(|e| format!("ERR_NATIVE_EXPORT_FAILED: {e}"))?;
    Ok(dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "export".to_string()))
}

/// Dialog pre-fill for a table export, mirroring the worker's own export
/// naming (`${table}.${format}`, excel degrading to csv — worker.js
/// exportTable). `args` is webview input: the result is used strictly as a
/// FILE NAME (final component only), exactly like save_file_as treats its
/// x-default-name header — a table named "../../x" cannot steer the dialog.
fn export_table_default_name(args: &serde_json::Value) -> String {
    let table = args
        .pointer("/0/table")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty())
        .unwrap_or("export");
    let ext = match args.pointer("/4/format").and_then(|v| v.as_str()) {
        Some("json") => "json",
        Some("sql") => "sql",
        // csv, "excel" (the worker emits CSV content for it), unknown, absent.
        _ => "csv",
    };
    let name = format!("{table}.{ext}");
    Path::new(&name)
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| "export.csv".to_string())
}

/// Dialog + export + atomic move, shared by both export commands. Returns the
/// bridge contract's wire shape: `{success:false}` on dialog cancel,
/// `{success:true, savedAs}` on success; real failures are structured Errs.
fn export_command(
    app: &AppHandle,
    window: &tauri::Window,
    core: &SidecarCore,
    method: &str,
    args: Option<serde_json::Value>,
    default_name: &str,
) -> Result<serde_json::Value, String> {
    // No dialog for a database whose file was replaced underneath the sidecar:
    // the export would copy the orphaned inode. The page retires it on this.
    assert_file_current(core)?;
    let Some(dest) = crate::file_dialog(app, window).set_file_name(default_name).blocking_save_file()? else {
        return Ok(serde_json::json!({ "success": false }));
    };
    if let Some(refusal) = destination_refusal(&app.state::<OpenFiles>(), &dest) {
        return Err(refusal);
    }
    let saved_as = export_to_dest(core, method, args, &dest, EXPORT_TIMEOUT)?;
    Ok(serde_json::json!({ "success": true, "savedAs": saved_as }))
}

// ---------------------------------------------------------------------------
// Commands (the ONLY webview-reachable surface this module adds)
// ---------------------------------------------------------------------------

// WHERE THESE RUN. Two facts, and they point in opposite directions:
//   * A SYNC `#[tauri::command]` runs on the MAIN thread under tauri://.
//     Everything here blocks (spawn + 10 s handshake, the shutdown reap, a
//     dialog, a file write), so none of it may run there — that is the F8
//     deadlock.
//   * `#[tauri::command(async)]` on a sync body is NOT "off the main thread
//     and therefore fine": tauri compiles it to `async_runtime::spawn`, i.e.
//     a WORKER of the shared multi-thread tokio runtime, whose worker count
//     is `available_parallelism()`. Blocking one of those is blocking a
//     scarce shared resource — with 12 workers and 16 sidecars per window, a
//     page could park every worker and stop dispatch for every command in
//     every window.
// So each command below is an `async fn` that immediately hands its blocking
// body to `spawn_blocking` (tokio's dedicated blocking pool, which grows on
// demand and is what "a sync fn wrapped in an async command" actually wants).
// `native_rpc` is the exception and does something better: it awaits, because
// its wait is the unbounded one.
//
// WINDOW SCOPING. Every command below resolves its registry from `window`,
// which Tauri fills in from the webview that sent the message
// (`CommandArg for Window` → `command.message.webview().window()`) — it is
// NOT an argument the page supplies, so a page cannot name another window's
// registry. That is what makes the DbId authority hold ACROSS windows as
// well as within one: an id issued in window 1 is simply absent from window
// 2's map, so it collapses to the same ERR_NATIVE_UNKNOWN_DB refusal as any
// other unknown id, and can never be retargeted onto a live sidecar.

#[tauri::command]
pub(crate) async fn native_available(app: AppHandle) -> Result<bool, String> {
    crate::blocking(move || Ok(locate_native_dir(&native_dir_candidates(&app)).is_some())).await
}

/// Opens a NEW sidecar for an already-allowlisted path and returns the DbId
/// every later call must carry, plus the canonical bound path. The sidecar
/// belongs to the calling window's registry; the allowlist it is checked
/// against stays app-global (a path the user picked is picked, whichever
/// window they picked it from), as does the hold on the file itself
/// (`OpenFiles` — two windows must not edit one database).
///
/// `max_bytes` is the page's configured maxFileSize (0/absent = unlimited),
/// refused BEFORE the spawn with `ERR_FILE_TOO_LARGE` — the same bound
/// `read_database_bytes` applies, so the two engines agree on what opens.
#[tauri::command]
pub(crate) async fn native_open(
    app: AppHandle,
    window: tauri::Window,
    path: String,
    read_only: bool,
    max_bytes: Option<u64>,
) -> Result<OpenedDatabase, String> {
    let label = window.label().to_string();
    let state = crate::window_state(&app.state::<crate::Windows>(), &label);
    crate::blocking(move || {
        open_inner(
            &app,
            &app.state::<crate::SessionAllowlist>(),
            &app.state::<crate::OpenFiles>(),
            &state.sidecars,
            &label,
            &path,
            read_only,
            max_bytes,
        )
    })
    .await
}

/// The one command that must NOT go to the blocking pool either: a query has
/// no bound the shell controls, so `rpc_awaited` awaits rather than occupying
/// any thread — see its doc comment and `RPC_TIMEOUT`.
#[tauri::command]
pub(crate) async fn native_rpc(
    window: tauri::Window,
    db_id: String,
    envelope: String,
) -> Result<String, String> {
    let state = crate::window_state(&window.state::<crate::Windows>(), window.label());
    rpc_awaited(&state.sidecars, &db_id, &envelope).await
}

/// Closes one database by id. Not idempotent by design — see `close_inner`.
#[tauri::command]
pub(crate) async fn native_close(window: tauri::Window, db_id: String) -> Result<(), String> {
    let state = crate::window_state(&window.state::<crate::Windows>(), window.label());
    crate::blocking(move || {
        close_inner(
            &state.sidecars,
            &db_id,
            "ERR_NATIVE_SIDECAR_EXITED: closed by native_close",
        )
    })
    .await
}

/// Whole-database export (VACUUM INTO) to a dialog-picked destination. The
/// webview triggers this but names NOTHING: dest is the user's pick, the temp
/// is the shell's own, and the shell-export envelope is built right here.
/// Blocking dialog + bounded sidecar wait, so the body goes to the blocking
/// pool — see `crate::blocking`.
#[tauri::command]
pub(crate) async fn native_export_database(
    app: AppHandle,
    window: tauri::Window,
    db_id: String,
) -> Result<serde_json::Value, String> {
    let state = crate::window_state(&window.state::<crate::Windows>(), window.label());
    let core = core_for(&state.sidecars, &db_id)?;
    // Pre-fill the dialog with the bound DB's own file name — shell state,
    // never webview input (matches the WASM route's `currentName` default).
    let default_name = Path::new(&core.bound_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("export")
        .to_string();
    crate::blocking(move || export_command(&app, &window, &core, "exportDatabase", None, &default_name)).await
}

/// Table export to a dialog-picked destination. `args_json` is the worker's
/// positional exportTable argument array, forwarded to the sidecar VERBATIM
/// (parsed, then embedded as JSON — never spliced into the envelope text). It
/// is webview-authored and carries the same authority as the rpc-route
/// exportTable args it replaces: table names, formats, options — no paths.
#[tauri::command]
pub(crate) async fn native_export_table(
    app: AppHandle,
    window: tauri::Window,
    db_id: String,
    args_json: String,
) -> Result<serde_json::Value, String> {
    let state = crate::window_state(&window.state::<crate::Windows>(), window.label());
    let core = core_for(&state.sidecars, &db_id)?;
    let args: serde_json::Value = serde_json::from_str(&args_json)
        .map_err(|e| format!("ERR_NATIVE_EXPORT_FAILED: export args are not valid JSON: {e}"))?;
    if !args.is_array() {
        // The sidecar would refuse this too; refusing here costs the user no
        // dialog and no temp dir.
        return Err(
            "ERR_NATIVE_EXPORT_FAILED: export args must be a JSON array (the worker's positional exportTable arguments)"
                .to_string(),
        );
    }
    let default_name = export_table_default_name(&args);
    crate::blocking(move || {
        export_command(&app, &window, &core, "exportTable", Some(args), &default_name)
    })
    .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[cfg(unix)]
    #[test]
    fn a_destination_symlink_is_judged_by_its_own_name() {
        // The write replaces the link itself, so the new file's logs are the
        // ones beside the link's name, not beside its target's.
        let dir = std::env::temp_dir().join(format!("sqx-dest-link-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let files = OpenFiles::default();
        fs::write(dir.join("target.sqlite"), b"SQLite format 3\0").unwrap();
        fs::write(dir.join("target.sqlite-wal"), [0u8; 4096]).unwrap();
        std::os::unix::fs::symlink(dir.join("target.sqlite"), dir.join("link.sqlite")).unwrap();
        assert_eq!(destination_refusal(&files, &dir.join("link.sqlite")), None, "the target's log is not the new file's");
        fs::write(dir.join("link.sqlite-wal"), [0u8; 4096]).unwrap();
        assert!(destination_refusal(&files, &dir.join("link.sqlite")).is_some_and(|r| r.starts_with("ERR_DESTINATION_HAS_LOG")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_destination_check_stats_no_folder_under_the_registry_lock() {
        // set_unsaved_state takes the same lock on the main thread: a folder on
        // a volume that stops answering must not freeze every window.
        let source = include_str!("native.rs");
        let body = source.split("pub(crate) fn destination_refusal").nth(1).expect("destination_refusal");
        let body = &body[..body.find("\n}\n").expect("end")];
        let released = body.find("holders.keys().cloned().collect()").expect("the held paths are copied out under the lock");
        let stat = body.find("named_destination_refusal(").expect("the open databases are compared");
        let long = body.find("long_name(").expect("the long name is read");
        assert!(released < stat && released < long, "nothing is stat-ed until the lock is released");
        assert!(!body[..released].contains("identity("), "nothing is stat-ed under the lock");
    }

    #[test]
    fn an_export_never_writes_beside_a_log_sqlite_would_apply_to_it() {
        // Not open here, but a -wal holding frames or a live journal sits
        // beside the destination: SQLite's next open would apply it to the new
        // file, whether a program still has it open or it is a crash leftover.
        let dir = std::env::temp_dir().join(format!("sqx-dest-log-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let files = OpenFiles::default();
        let dest = dir.join("other.sqlite");
        fs::write(&dest, b"SQLite format 3\0").unwrap();
        assert_eq!(destination_refusal(&files, &dest), None, "no log");
        fs::write(dir.join("other.sqlite-wal"), [0u8; 32]).unwrap();
        assert_eq!(destination_refusal(&files, &dest), None, "a WAL header alone");
        fs::write(dir.join("other.sqlite-wal"), [0u8; 4096]).unwrap();
        assert!(destination_refusal(&files, &dest).is_some_and(|r| r.starts_with("ERR_DESTINATION_HAS_LOG")));
        fs::remove_file(dir.join("other.sqlite-wal")).unwrap();
        let mut hot = vec![0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
        hot.resize(512, 0);
        // A destination that does not exist yet, with a journal left beside its name.
        fs::write(dir.join("fresh.sqlite-journal"), &hot).unwrap();
        assert!(destination_refusal(&files, &dir.join("fresh.sqlite")).is_some_and(|r| r.starts_with("ERR_DESTINATION_HAS_LOG")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_export_never_writes_over_an_open_database_or_its_journals() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("db.sqlite");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let canonical = fs::canonicalize(&db).unwrap();
        let files = OpenFiles::default();
        let hold = claim_native(&files, &canonical, "main").unwrap();

        for name in ["db.sqlite", "db.sqlite-wal", "db.sqlite-shm", "db.sqlite-journal"] {
            let refusal = destination_refusal(&files, &dir.join(name));
            assert!(refusal.as_deref().is_some_and(|r| r.contains("open in SQLite Explorer")), "{name}: {refusal:?}");
        }
        // Another case is the same file only where the volume folds case.
        let folds = fs::symlink_metadata(dir.join("DB.SQLITE")).is_ok();
        let refusal = destination_refusal(&files, &dir.join("DB.SQLITE-Journal"));
        assert_eq!(refusal.as_deref().is_some_and(|r| r.contains("open in SQLite Explorer")), folds, "{refusal:?}");
        for name in ["db.sqlite.csv", "other.sqlite", "db.sqlite-wal.bak"] {
            assert_eq!(destination_refusal(&files, &dir.join(name)), None, "{name}");
        }
        // An open database with a live WAL is still named as the open one,
        // not as a file some other program holds.
        fs::write(dir.join("db.sqlite-wal"), [0u8; 4096]).unwrap();
        assert!(destination_refusal(&files, &db).is_some_and(|r| r.starts_with("ERR_DESTINATION_OPEN")));
        fs::remove_file(dir.join("db.sqlite-wal")).unwrap();
        // The same name in another folder is another file.
        let elsewhere = dir.join("sub");
        fs::create_dir_all(&elsewhere).unwrap();
        assert_eq!(destination_refusal(&files, &elsewhere.join("db.sqlite")), None);
        // …and a log beside it is still found while a database is open.
        fs::write(elsewhere.join("db.sqlite-wal"), [0u8; 4096]).unwrap();
        assert!(destination_refusal(&files, &elsewhere.join("db.sqlite")).is_some_and(|r| r.starts_with("ERR_DESTINATION_HAS_LOG")));
        fs::remove_file(elsewhere.join("db.sqlite-wal")).unwrap();

        drop(hold);
        assert_eq!(destination_refusal(&files, &db), None, "a closed database is not refused");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The volume decides which spellings name one file: on a case-insensitive
    /// volume (APFS's default, NTFS) "É.db" and "é.db" are one file, and
    /// APFS treats a name's NFC and NFD spellings as one as well. The
    /// expectation is read from the volume itself, so the test holds on a
    /// volume that folds neither.
    #[test]
    fn an_open_database_is_refused_under_every_spelling_its_volume_resolves_to_it() {
        let root = std::env::temp_dir().join(format!("sqx-dest-fold-{}-{}", std::process::id(), line!()));
        let files = OpenFiles::default();
        // (the open database, then destinations and the database name each one's
        // journal suffix leaves)
        let cases: [(&str, &[(&str, &str)]); 2] = [
            ("\u{c9}.db", &[("\u{e9}.db", "\u{e9}.db"), ("\u{e9}.db-wal", "\u{e9}.db"), ("\u{e9}.DB-Journal", "\u{e9}.DB")]),
            ("\u{e9}.db", &[("e\u{301}.db", "e\u{301}.db"), ("e\u{301}.db-shm", "e\u{301}.db")]),
        ];
        let mut wrong = Vec::new();
        for (i, (open, destinations)) in cases.iter().enumerate() {
            let dir = root.join(i.to_string());
            fs::create_dir_all(&dir).unwrap();
            let db = dir.join(open);
            fs::write(&db, b"SQLite format 3\0").unwrap();
            let hold = claim_native(&files, &fs::canonicalize(&db).unwrap(), "main").unwrap();
            for (name, base) in destinations.iter() {
                let same_file = fs::symlink_metadata(dir.join(base)).is_ok();
                let refusal = destination_refusal(&files, &dir.join(name));
                // Not refused means no refusal at all, not merely not this one: where the
                // volume does not make the name the open database's, nothing of the name
                // a journal suffix leaves is there either.
                let right = if same_file {
                    refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_OPEN"))
                } else {
                    refusal.is_none()
                };
                if !right {
                    wrong.push(format!("{open:?} open, {name:?} picked (same file: {same_file}): {refusal:?}"));
                }
            }
            drop(hold);
        }
        fs::remove_dir_all(&root).unwrap();
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// A journal file that exists is matched by identity under every spelling the
    /// volume resolves to it: APFS folds U+017F (long s) onto s, so "x.db-ſhm"
    /// names the live "x.db-shm", and a Save As there would replace the wal-index
    /// another connection is using. A journal name that does not exist yet is
    /// matched by spelling: any ASCII case, and U+017F for an s.
    #[test]
    fn a_destination_resolving_to_an_open_databases_journal_is_refused_in_any_spelling() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-journal-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("x.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let files = OpenFiles::default();
        let _hold = claim_native(&files, &fs::canonicalize(&db).unwrap(), "main").unwrap();
        let open = |name: &str| {
            destination_refusal(&files, &dir.join(name)).is_some_and(|r| r.starts_with("ERR_DESTINATION_OPEN"))
        };
        let long_s = "x.db-\u{17f}hm";

        // No -shm yet: still refused, under the long-s spelling too, so that a
        // connection opening the database in WAL mode while the write is under
        // way cannot have its new -shm replaced through that spelling.
        assert!(open(long_s), "the long-s spelling of -shm before a -shm exists");
        assert!(open("x.db-SHM") && open("x.db-shm"), "an ASCII spelling of the suffix");
        assert!(open("x.db-\u{17f}HM"), "long s with the rest of the suffix in another case");
        assert_eq!(destination_refusal(&files, &dir.join("x.db-\u{17f}")), None, "not a journal suffix");

        fs::write(dir.join("x.db-shm"), [0u8; 32768]).unwrap();
        // Refused on every volume: where the volume folds it (APFS) it is the
        // live -shm, matched by identity; where it does not (ext4), it is
        // refused by spelling, the safe way to be wrong, as x.db-WAL is.
        assert!(open(long_s), "the long-s spelling of a live -shm");
        assert!(open("x.db-SHM") && open("x.db-shm"));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Only "no such file" says a destination is not an open database. Any
    /// other answer, here a folder this user cannot search, refuses rather
    /// than writes unchecked.
    #[cfg(unix)]
    #[test]
    fn a_destination_that_cannot_be_checked_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sqx-dest-unchecked-{}-{}", std::process::id(), line!()));
        let locked = dir.join("locked");
        fs::create_dir_all(locked.join("sub")).unwrap();
        let db = dir.join("open.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let files = OpenFiles::default();
        let _hold = claim_native(&files, &fs::canonicalize(&db).unwrap(), "main").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let denied = fs::symlink_metadata(locked.join("sub").join("open.db")).is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
        let refusal = destination_refusal(&files, &locked.join("sub").join("open.db"));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        if !denied {
            eprintln!("a mode-000 folder is searchable here (root?); unchecked-destination test skipped");
            return;
        }
        assert!(refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_UNCHECKED")), "{refusal:?}");
    }

    /// Only "no such file" says there is no log beside a destination. A log there that
    /// cannot be opened, or a folder that cannot be resolved, refuses the write as
    /// unchecked.
    #[cfg(unix)]
    #[test]
    fn a_destination_whose_logs_cannot_be_looked_at_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sqx-dest-log-unchecked-{}-{}", std::process::id(), line!()));
        let locked = dir.join("locked");
        fs::create_dir_all(locked.join("sub")).unwrap();
        let files = OpenFiles::default();
        let dest = dir.join("other.sqlite");
        let mut header = b"SQLite format 3\0".to_vec();
        header.resize(100, 0);
        header[18] = 1;
        header[19] = 1;
        fs::write(&dest, &header).unwrap();
        let wal = dir.join("other.sqlite-wal");
        fs::write(&wal, [0u8; 4152]).unwrap();
        fs::set_permissions(&wal, fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let denied = fs::File::open(&wal).is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied)
            && fs::canonicalize(locked.join("sub")).is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
        let beside_log = destination_refusal(&files, &dest);
        let in_locked = destination_refusal(&files, &locked.join("sub").join("new.sqlite"));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&wal, fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        // Not enforced for root: the cases would prove nothing.
        assert!(denied, "mode 000 is not enforced here");
        assert!(
            beside_log.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_UNCHECKED") && r.contains("other.sqlite-wal")),
            "{beside_log:?}"
        );
        assert!(in_locked.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_UNCHECKED")), "{in_locked:?}");
    }

    /// An open database whose own entry cannot be looked at (its share went
    /// away, or it lost search permission) still fails closed, but the refusal
    /// names WHICH database, by file name only, and what to do.
    #[cfg(unix)]
    #[test]
    fn an_unreachable_open_database_is_named_in_the_refusal() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sqx-dest-held-unreachable-{}-{}", std::process::id(), line!()));
        let locked = dir.join("locked");
        fs::create_dir_all(&locked).unwrap();
        let far = locked.join("far.db");
        fs::write(&far, b"SQLite format 3\0").unwrap();
        let existing = dir.join("existing.db");
        fs::write(&existing, b"SQLite format 3\0").unwrap();
        let files = OpenFiles::default();
        let _hold = claim_native(&files, &fs::canonicalize(&far).unwrap(), "main").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let denied = fs::symlink_metadata(&far).is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
        let refusal = destination_refusal(&files, &existing);
        let fresh = destination_refusal(&files, &dir.join("new.db"));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        if !denied {
            eprintln!("a mode-000 folder is searchable here (root?); unreachable-database test skipped");
            return;
        }
        let refusal = refusal.expect("fails closed");
        assert!(refusal.starts_with("ERR_DESTINATION_UNCHECKED"), "{refusal}");
        assert!(refusal.contains("\"far.db\"") && refusal.contains("\"existing.db\""), "{refusal}");
        assert!(!refusal.contains(&*locked.to_string_lossy()), "names the file, never its path: {refusal}");
        // A name that does not exist yet needs no look at the open databases.
        assert_eq!(fresh, None);
    }

    /// A name ending in a journal suffix is refused, whatever is open, when the name it
    /// starts with is a regular file, or a link to one: SQLite reads such a file as that
    /// database's journal. With nothing of that name beside it, or a folder, or a link
    /// to nothing, it is a file like any other ("trip-journal" with no "trip", and
    /// "notes-journal" beside a folder "notes"). Every spelling the suffix match takes
    /// is covered (any ASCII case, U+017F for an s); whether "X.DB" names x.db is the
    /// volume's to say.
    #[test]
    fn a_destination_named_like_a_journal_is_refused_when_its_database_is_there() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-journal-name-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let files = OpenFiles::default();
        let journal_named = ["x.db-wal", "x.db-shm", "x.db-journal", "x.db-JOURNAL", "x.db-\u{17f}hm"];
        let mut wrong = Vec::new();
        let expect = |name: &str, base_there: bool, wrong: &mut Vec<String>| {
            let refusal = destination_refusal(&files, &dir.join(name));
            let right = if base_there {
                refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_JOURNAL_NAME"))
            } else {
                refusal.is_none()
            };
            if !right {
                wrong.push(format!("{name} (base there: {base_there}): {refusal:?}"));
            }
        };
        // Nothing at x.db, then a file, then a folder.
        for make in [None, Some(false), Some(true)] {
            match make {
                Some(false) => fs::write(dir.join("x.db"), b"SQLite format 3\0").unwrap(),
                Some(true) => fs::create_dir(dir.join("x.db")).unwrap(),
                None => {}
            }
            let a_file = make == Some(false);
            for name in journal_named {
                expect(name, a_file, &mut wrong);
            }
            expect("X.DB-WAL", a_file && fs::symlink_metadata(dir.join("X.DB")).is_ok(), &mut wrong);
            for name in ["x.db-wal.bak", "x.db-\u{17f}", "-wal", "x.db-walnut"] {
                expect(name, false, &mut wrong);
            }
            match make {
                Some(false) => fs::remove_file(dir.join("x.db")).unwrap(),
                Some(true) => fs::remove_dir(dir.join("x.db")).unwrap(),
                None => {}
            }
        }
        // A link counts as what it points to: a file, a folder, or nothing.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.join("nowhere"), dir.join("x.db")).unwrap();
            expect("x.db-wal", false, &mut wrong);
            fs::write(dir.join("target.db"), b"SQLite format 3\0").unwrap();
            fs::remove_file(dir.join("x.db")).unwrap();
            std::os::unix::fs::symlink(dir.join("target.db"), dir.join("x.db")).unwrap();
            expect("x.db-wal", true, &mut wrong);
            fs::create_dir(dir.join("notes")).unwrap();
            std::os::unix::fs::symlink(dir.join("notes"), dir.join("folder-link")).unwrap();
            expect("folder-link-journal", false, &mut wrong);
        }
        // A plain file of the base name, whatever it holds, could be opened as a database.
        fs::write(dir.join("trip"), b"a text file").unwrap();
        expect("trip-wal", true, &mut wrong);
        fs::remove_dir_all(&dir).unwrap();
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// A base name that cannot be looked up is not known to be absent.
    #[cfg(unix)]
    #[test]
    fn a_journal_named_destination_whose_database_cannot_be_looked_up_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sqx-dest-journal-locked-{}-{}", std::process::id(), line!()));
        let locked = dir.join("locked");
        fs::create_dir_all(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let denied = fs::symlink_metadata(locked.join("x.db")).is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
        let refusal = destination_refusal(&OpenFiles::default(), &locked.join("x.db-wal"));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        // Not enforced for root: the case would prove nothing.
        assert!(denied, "a mode-000 folder is searchable here");
        assert!(
            refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_UNCHECKED") && r.contains("\"x.db\"")),
            "{refusal:?}"
        );
    }

    /// The name Win32 will write, from the name a destination was picked by. Run on
    /// every platform; applied by `destination_refusal` on Windows only.
    #[test]
    fn a_destination_name_is_normalized_as_win32_resolves_it() {
        use std::ffi::{OsStr, OsString};
        let written = |name: &str| win32_final_name(OsStr::new(name));
        for (picked, name) in [
            ("x.db-shm.", "x.db-shm"),
            ("x.db-journal ", "x.db-journal"),
            ("x.db-wal::$DATA", "x.db-wal"),
            ("x.db-WAL::$data", "x.db-WAL"),
            ("x.db-wal. ::$DATA . ", "x.db-wal"),
            ("\u{e9}.db-shm..", "\u{e9}.db-shm"),
            ("x.db", "x.db"),
            (".x.db", ".x.db"),
        ] {
            assert_eq!(written(picked), Ok(OsString::from(name)), "{picked:?}");
        }
        for (picked, code) in [
            ("...", "ERR_DESTINATION_UNCHECKED"),
            (" . ", "ERR_DESTINATION_UNCHECKED"),
            ("::$DATA", "ERR_DESTINATION_UNCHECKED"),
            ("x.db:evil", "ERR_DESTINATION_STREAM"),
            ("x.db-wal:s:$DATA", "ERR_DESTINATION_STREAM"),
            ("x.db::$INDEX_ALLOCATION", "ERR_DESTINATION_STREAM"),
        ] {
            assert_eq!(written(picked).map_err(|(code, _)| code), Err(code), "{picked:?}");
        }
    }

    /// On Windows a journal file reached by a spelling Win32 resolves to it is refused
    /// like the journal file itself, and a stream name is refused outright.
    #[cfg(windows)]
    #[test]
    fn win32_spellings_of_journal_files_are_refused_on_windows() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-win32-names-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("x.db"), b"SQLite format 3\0").unwrap();
        let files = OpenFiles::default();
        let code = |name: &str| destination_refusal(&files, &dir.join(name)).map(|r| r[..r.find(':').unwrap()].to_string());
        let mut wrong = Vec::new();
        for (name, want) in [
            ("x.db-journal ", "ERR_DESTINATION_JOURNAL_NAME"),
            ("x.db-WAL::$DATA", "ERR_DESTINATION_JOURNAL_NAME"),
            ("x.db-shm.", "ERR_DESTINATION_JOURNAL_NAME"),
            ("x.db:evil", "ERR_DESTINATION_STREAM"),
            ("...", "ERR_DESTINATION_UNCHECKED"),
        ] {
            if code(name).as_deref() != Some(want) {
                wrong.push(format!("{name:?} (x.db not open): {:?}", code(name)));
            }
        }
        // Open, with its -shm there: the journal by identity, the database by its own.
        fs::write(dir.join("x.db-shm"), [0u8; 32768]).unwrap();
        let hold = claim_native(&files, &fs::canonicalize(dir.join("x.db")).unwrap(), "main").unwrap();
        for name in ["x.db-shm.", "x.db-SHM::$DATA", "x.db.", "x.db::$DATA"] {
            if code(name).as_deref() != Some("ERR_DESTINATION_OPEN") {
                wrong.push(format!("{name:?} (x.db open): {:?}", code(name)));
            }
        }
        drop(hold);
        fs::remove_dir_all(&dir).unwrap();
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// The read hold refuses a file it cannot key on its own, not only behind the read
    /// gate's first look: a link whose target is gone is there but has no location.
    #[cfg(unix)]
    #[test]
    fn the_read_hold_refuses_a_file_it_cannot_key() {
        let dir = std::env::temp_dir().join(format!("sqx-hold-unresolvable-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(dir.join("gone.db"), dir.join("x.db")).unwrap();
        let held = hold_for_read(&OpenFiles::default(), &dir.join("x.db"), "main");
        let absent = hold_for_read(&OpenFiles::default(), &dir.join("absent.db"), "main");
        fs::remove_dir_all(&dir).unwrap();
        assert!(held.as_ref().is_err_and(|r| r.starts_with("ERR_FILE_MISSING")), "{held:?}");
        assert_eq!(absent, Ok(()), "a name that is not there adds no refusal: the read fails on its own");
    }

    /// The spellings a destination is judged by, and that any of them can draw the
    /// refusal: here the 8.3 short name of x.db-wal, which matches no rule, and its long
    /// name, which does. Run on every platform; the Windows-only tests below use real
    /// short names.
    #[test]
    fn a_destination_is_judged_by_every_spelling_of_its_name() {
        use std::ffi::{OsStr, OsString};
        let short = OsStr::new("XDBWAL~1");
        assert_eq!(destination_spellings(short, Ok(None)).unwrap(), vec![OsString::from("XDBWAL~1")]);
        assert_eq!(
            destination_spellings(short, Ok(Some(OsString::from("x.db-wal")))).unwrap(),
            vec![OsString::from("XDBWAL~1"), OsString::from("x.db-wal")]
        );
        assert_eq!(destination_spellings(OsStr::new("x.db"), Ok(Some(OsString::from("x.db")))).unwrap().len(), 1);
        assert!(destination_spellings(short, Err(io::Error::from_raw_os_error(5))).is_err());
        let dir = std::env::temp_dir().join(format!("sqx-dest-spellings-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("x.db"), b"SQLite format 3\0").unwrap();
        let both = named_destination_refusal(&[], &dir, &[OsString::from("XDBWAL~1"), OsString::from("x.db-wal")], "XDBWAL~1");
        let short_only = named_destination_refusal(&[], &dir, &[OsString::from("XDBWAL~1")], "XDBWAL~1");
        fs::remove_dir_all(&dir).unwrap();
        assert!(both.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_JOURNAL_NAME")), "{both:?}");
        assert_eq!(short_only, None);
    }

    /// The log check looks beside every spelling of the destination: here an 8.3 short
    /// name, beside which nothing is, and the long name of a closed database whose -wal
    /// holds frames. Run on every platform.
    #[test]
    fn a_log_beside_any_spelling_of_a_destination_refuses_it() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-log-spellings-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("long name.db"), b"SQLite format 3\0").unwrap();
        fs::write(dir.join("long name.db-wal"), [0u8; 4096]).unwrap();
        let both = destination_log_refusal(&[dir.join("LONGNA~1.DB"), dir.join("long name.db")], "LONGNA~1.DB");
        let short_only = destination_log_refusal(&[dir.join("LONGNA~1.DB")], "LONGNA~1.DB");
        fs::remove_dir_all(&dir).unwrap();
        assert!(both.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_HAS_LOG")), "{both:?}");
        assert_eq!(short_only, None);
    }

    /// The 8.3 short name of a closed database whose -wal holds frames is refused like
    /// the database's own name. A volume that makes no short names is skipped, said.
    #[cfg(windows)]
    #[test]
    fn an_8_3_name_of_a_database_with_a_log_is_refused_on_windows() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-short-log-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("long database name.sqlite");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        fs::write(dir.join("long database name.sqlite-wal"), [0u8; 4096]).unwrap();
        let short = crate::windows_file_info::short_name(&db).unwrap().expect("the database is there");
        if short.eq_ignore_ascii_case("long database name.sqlite") {
            fs::remove_dir_all(&dir).unwrap();
            eprintln!("skipped: this volume makes no 8.3 names");
            return;
        }
        let refusal = destination_refusal(&OpenFiles::default(), &dir.join(&short));
        fs::remove_dir_all(&dir).unwrap();
        assert!(refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_HAS_LOG")), "{short:?}: {refusal:?}");
    }

    /// A destination whose path is longer than MAX_PATH (260 characters) is judged like
    /// any other: its long name is read through a verbatim path rather than failing as
    /// unchecked or being skipped.
    #[cfg(windows)]
    #[test]
    fn a_destination_past_max_path_is_judged_by_its_long_name_on_windows() {
        let mut dir = std::env::temp_dir().join(format!("sqx-dest-long-path-{}-{}", std::process::id(), line!()));
        let root = dir.clone();
        while dir.as_os_str().len() < 300 {
            dir.push("a-folder-name-long-enough-to-pass-max-path-quickly-0123456789");
        }
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("x.db"), b"SQLite format 3\0").unwrap();
        fs::write(dir.join("x.db-wal"), [0u8; 32]).unwrap();
        let wal = dir.join("x.db-wal");
        let long = crate::windows_file_info::long_name(&wal);
        let journal = destination_refusal(&OpenFiles::default(), &wal);
        let fresh = destination_refusal(&OpenFiles::default(), &dir.join("new.db"));
        // Its 8.3 short name, where the volume makes them, draws the same refusal.
        let short = crate::windows_file_info::short_name(&wal);
        let by_short = match &short {
            Ok(Some(short)) if !short.eq_ignore_ascii_case("x.db-wal") => Some(destination_refusal(&OpenFiles::default(), &dir.join(short))),
            _ => None,
        };
        fs::remove_dir_all(&root).unwrap();
        assert!(wal.as_os_str().len() > 260, "the path is past MAX_PATH");
        assert_eq!(long.unwrap(), Some(std::ffi::OsString::from("x.db-wal")));
        assert!(journal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_JOURNAL_NAME")), "{journal:?}");
        assert_eq!(fresh, None, "a new name past MAX_PATH is not refused as unchecked");
        assert!(short.as_ref().is_ok_and(|s| s.is_some()), "{short:?}");
        match by_short {
            Some(refusal) => assert!(refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_JOURNAL_NAME")), "{short:?}: {refusal:?}"),
            None => eprintln!("8.3 half skipped: this volume makes no 8.3 names"),
        }
    }

    /// The 8.3 short name of an existing journal file is judged by its long name too.
    /// A volume that makes no short names (8.3 creation can be off) is skipped, said.
    #[cfg(windows)]
    #[test]
    fn an_8_3_name_of_a_journal_file_is_judged_by_its_long_name_on_windows() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-short-wal-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("x.db"), b"SQLite format 3\0").unwrap();
        fs::write(dir.join("x.db-wal"), [0u8; 32]).unwrap();
        let short = crate::windows_file_info::short_name(&dir.join("x.db-wal")).unwrap().expect("x.db-wal is there");
        if short.eq_ignore_ascii_case("x.db-wal") {
            fs::remove_dir_all(&dir).unwrap();
            eprintln!("skipped: this volume makes no 8.3 names (x.db-wal's short name is itself)");
            return;
        }
        let refusal = destination_refusal(&OpenFiles::default(), &dir.join(&short));
        fs::remove_dir_all(&dir).unwrap();
        assert!(refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_JOURNAL_NAME")), "{short:?}: {refusal:?}");
    }

    /// A journal-named destination spelled with the database's 8.3 short name ("LONGDA~1.SQL-wal")
    /// is refused: the volume resolves the short name when the database is looked up.
    #[cfg(windows)]
    #[test]
    fn an_8_3_name_of_the_database_counts_for_the_journal_rule_on_windows() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-short-base-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("long database name.sqlite");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let short = crate::windows_file_info::short_name(&db).unwrap().expect("the database is there");
        if short.eq_ignore_ascii_case("long database name.sqlite") {
            fs::remove_dir_all(&dir).unwrap();
            eprintln!("skipped: this volume makes no 8.3 names");
            return;
        }
        let mut journal = short.clone();
        journal.push("-wal");
        let refusal = destination_refusal(&OpenFiles::default(), &dir.join(&journal));
        fs::remove_dir_all(&dir).unwrap();
        assert!(refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_JOURNAL_NAME")), "{journal:?}: {refusal:?}");
    }

    /// A destination whose own entry is one of an open database's journal files
    /// now, whatever it is called (here a hard link with no journal suffix to the
    /// live -shm), is refused as that journal: only the identity comparison with
    /// the open databases' journal files can see it.
    #[test]
    fn a_link_to_an_open_databases_live_shm_is_refused_whatever_its_name() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-shm-link-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("x.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        fs::write(dir.join("x.db-shm"), [0u8; 32768]).unwrap();
        fs::hard_link(dir.join("x.db-shm"), dir.join("alias.bin")).unwrap();
        let files = OpenFiles::default();
        let hold = claim_native(&files, &fs::canonicalize(&db).unwrap(), "main").unwrap();
        let refusal = destination_refusal(&files, &dir.join("alias.bin"));
        drop(hold);
        let closed = destination_refusal(&files, &dir.join("alias.bin"));
        fs::remove_dir_all(&dir).unwrap();
        assert!(refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_OPEN")), "{refusal:?}");
        assert_eq!(closed, None, "once the database is closed it is a file like any other");
    }

    /// Windows resolves a trailing dot away ("x.db-shm." opens x.db-shm), so with
    /// the -shm present that spelling is the live -shm, matched by identity.
    #[cfg(windows)]
    #[test]
    fn a_trailing_dot_spelling_of_a_live_shm_is_refused_on_windows() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-shm-dot-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("x.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        fs::write(dir.join("x.db-shm"), [0u8; 32768]).unwrap();
        let files = OpenFiles::default();
        let _hold = claim_native(&files, &fs::canonicalize(&db).unwrap(), "main").unwrap();
        let same_file = entry_identity(&dir.join("x.db-shm.")).ok() == entry_identity(&dir.join("x.db-shm")).ok();
        let refusal = destination_refusal(&files, &dir.join("x.db-shm."));
        fs::remove_dir_all(&dir).unwrap();
        assert!(same_file, "Windows did not resolve the trailing dot to x.db-shm");
        assert!(refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_OPEN")), "{refusal:?}");
    }

    /// Identity cannot tell one link to a file from another, so a hard link to
    /// an open database is refused like the database, though writing there
    /// would only replace that link.
    #[test]
    fn a_hard_link_to_an_open_database_is_refused_like_the_database() {
        let dir = std::env::temp_dir().join(format!("sqx-dest-hardlink-{}-{}", std::process::id(), line!()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("open.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        fs::hard_link(&db, dir.join("alias.db")).unwrap();
        let files = OpenFiles::default();
        let _hold = claim_native(&files, &fs::canonicalize(&db).unwrap(), "main").unwrap();
        for name in ["alias.db", "alias.db-wal"] {
            let refusal = destination_refusal(&files, &dir.join(name));
            assert!(refusal.as_deref().is_some_and(|r| r.starts_with("ERR_DESTINATION_OPEN")), "{name}: {refusal:?}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// No unit test can invoke the commands (they need a live AppHandle and a
    /// dialog), so the wiring is pinned on the source: both writers that take a
    /// user-picked destination consult the registry before they write.
    #[test]
    fn every_picked_destination_is_checked_against_the_open_databases() {
        let native = include_str!("native.rs");
        let export = native.split("fn export_command(").nth(1).expect("export_command");
        let export = &export[..export.find("\n}\n").expect("end of export_command")];
        assert!(export.find("destination_refusal").expect("checked") < export.find("export_to_dest").expect("written"));
        let lib = include_str!("lib.rs");
        let save_as = lib.split("async fn save_file_as").nth(1).expect("save_file_as");
        let save_as = &save_as[..save_as.find("fn urlencoding_decode").expect("decoder follows")];
        assert!(save_as.find("destination_refusal").expect("checked") < save_as.find("write_atomically").expect("written"));
    }

    /// Cross-language byte fixture: viewer/tests/fixtures/native-frames.{bin,json},
    /// the exact bytes the JS codec emits (`npm run native-frame-fixture` writes
    /// them; viewer/tests/unit/native_frame_codec.test.ts holds the JS side to the
    /// same files), so a divergence here is a wire break.
    const FIXTURE_BIN: &[u8] = include_bytes!("../../viewer/tests/fixtures/native-frames.bin");
    const FIXTURE_JSON: &str = include_str!("../../viewer/tests/fixtures/native-frames.json");

    fn manifest() -> serde_json::Value {
        serde_json::from_str(FIXTURE_JSON).expect("fixture manifest parses")
    }

    fn header_bytes(limits: &serde_json::Value, key: &str) -> [u8; 4] {
        let arr = limits[key].as_array().unwrap_or_else(|| panic!("{key} missing"));
        let mut out = [0u8; 4];
        for (i, v) in arr.iter().enumerate() {
            out[i] = v.as_u64().expect("header byte") as u8;
        }
        out
    }

    /// Every fixture frame decodes from the exact committed bytes: header
    /// bytes and declared length match the manifest, and the payload parses
    /// to structurally equal JSON (serde_json::Value equality — the proxy
    /// forwards bytes, it never re-serialises, so byte-identical re-encoding
    /// is deliberately NOT asserted).
    #[test]
    fn fixture_frames_decode_against_the_js_codec_bytes() {
        let manifest = manifest();
        let frames = manifest["frames"].as_array().expect("frames array");
        assert!(frames.len() >= 9, "fixture should carry the 9 pinned frames");
        let mut cursor = Cursor::new(FIXTURE_BIN);
        for frame in frames {
            let label = frame["label"].as_str().unwrap();
            let offset = frame["offset"].as_u64().unwrap();
            let declared = frame["payloadBytes"].as_u64().unwrap();
            let expected_header: Vec<u8> = frame["header"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect();
            assert_eq!(cursor.position(), offset, "stream aligned at {label:?}");
            let on_disk = &FIXTURE_BIN[offset as usize..offset as usize + 4];
            assert_eq!(on_disk, &expected_header[..], "header bytes of {label:?}");
            assert_eq!(
                u32::from_be_bytes(expected_header.try_into().unwrap()) as u64,
                declared,
                "declared length of {label:?}"
            );
            match read_frame(&mut cursor).unwrap() {
                InboundFrame::Frame(payload) => {
                    assert_eq!(payload.len() as u64, declared, "payload length of {label:?}");
                    let decoded: serde_json::Value =
                        serde_json::from_slice(&payload).expect("payload parses");
                    let expected: serde_json::Value =
                        serde_json::from_str(frame["payloadUtf8"].as_str().unwrap())
                            .expect("manifest payloadUtf8 parses");
                    assert_eq!(decoded, expected, "structural JSON equality of {label:?}");
                }
                other => panic!("{label:?} did not decode as a frame: {other:?}"),
            }
        }
        // Nothing but the manifested frames in the bin, and EOF is clean.
        assert_eq!(cursor.position() as usize, FIXTURE_BIN.len());
        assert!(matches!(read_frame(&mut cursor).unwrap(), InboundFrame::Eof));
    }

    /// The manifest's `limits` block pins the unsigned read, the inclusive
    /// cap, and both drain tiers — each header is fed through the REAL
    /// reader, not just a classifier.
    #[test]
    fn fixture_limits_pin_cap_and_both_tiers() {
        let manifest = manifest();
        let limits = &manifest["limits"];
        assert_eq!(limits["maxFrameBytes"].as_u64().unwrap(), MAX_FRAME_BYTES as u64);
        assert_eq!(limits["maxDrainBytes"].as_u64().unwrap(), MAX_DRAIN_BYTES);

        // maxHeader: exactly the cap — ACCEPTED (inclusive). 16 MiB of payload.
        let max_header = header_bytes(limits, "maxHeader");
        assert_eq!(u32::from_be_bytes(max_header) as u64, MAX_FRAME_BYTES as u64);
        let mut stream = max_header
            .as_slice()
            .chain(io::repeat(b'x').take(MAX_FRAME_BYTES as u64));
        match read_frame(&mut stream).unwrap() {
            InboundFrame::Frame(p) => assert_eq!(p.len() as u64, MAX_FRAME_BYTES as u64),
            other => panic!("cap-sized frame must be accepted, got {other:?}"),
        }

        // overMaxHeader: cap+1 — drained, and the stream RESYNCHRONISES: the
        // valid frame behind it still decodes.
        let over_max = header_bytes(limits, "overMaxHeader");
        let declared = u32::from_be_bytes(over_max) as u64;
        assert_eq!(declared, MAX_FRAME_BYTES as u64 + 1);
        let mut tail = Vec::new();
        write_frame(&mut tail, br#"{"after":"oversize"}"#).unwrap();
        let mut stream = over_max
            .as_slice()
            .chain(io::repeat(0u8).take(declared))
            .chain(tail.as_slice());
        assert!(matches!(
            read_frame(&mut stream).unwrap(),
            InboundFrame::Drained { declared: d } if d == declared
        ));
        match read_frame(&mut stream).unwrap() {
            InboundFrame::Frame(p) => assert_eq!(p, br#"{"after":"oversize"}"#),
            other => panic!("stream must resynchronise after a drain, got {other:?}"),
        }

        // maxDrainHeader: exactly 4×cap — still the drain tier (inclusive).
        let max_drain = header_bytes(limits, "maxDrainHeader");
        assert_eq!(u32::from_be_bytes(max_drain) as u64, MAX_DRAIN_BYTES);
        let mut stream = max_drain
            .as_slice()
            .chain(io::repeat(0u8).take(MAX_DRAIN_BYTES));
        assert!(matches!(
            read_frame(&mut stream).unwrap(),
            InboundFrame::Drained { declared } if declared == MAX_DRAIN_BYTES
        ));

        // overMaxDrainHeader: 4×cap+1 — unrecoverable desync, and the reader
        // consumes NOTHING past the header (no drain of the real stream).
        let over_drain = header_bytes(limits, "overMaxDrainHeader");
        let mut cursor = Cursor::new([over_drain.as_slice(), &[0xAA; 32][..]].concat());
        assert!(matches!(
            read_frame(&mut cursor).unwrap(),
            InboundFrame::Desync { declared } if declared == MAX_DRAIN_BYTES + 1
        ));
        assert_eq!(cursor.position(), 4, "desync must not consume past the header");

        // signedTrapHeader: 0x80000000. A signed reader would see a NEGATIVE
        // length, slip every cap check, and hang; the unsigned read
        // classifies it as what it is — far beyond the drain ceiling.
        let signed_trap = header_bytes(limits, "signedTrapHeader");
        let declared = u32::from_be_bytes(signed_trap) as u64;
        assert_eq!(declared, 0x8000_0000);
        assert!(declared > MAX_DRAIN_BYTES, "the trap must land in the fatal tier");
        let mut cursor = Cursor::new(signed_trap.to_vec());
        assert!(matches!(
            read_frame(&mut cursor).unwrap(),
            InboundFrame::Desync { declared: d } if d == declared
        ));

        // maxU32Header: 0xffffffff — fatal, never a 4 GiB drain.
        let max_u32 = header_bytes(limits, "maxU32Header");
        let mut cursor = Cursor::new(max_u32.to_vec());
        assert!(matches!(
            read_frame(&mut cursor).unwrap(),
            InboundFrame::Desync { declared } if declared == 0xffff_ffff
        ));
    }

    #[test]
    fn outbound_cap_is_inclusive_and_headers_are_big_endian() {
        // Exactly at the cap: accepted, header is the manifest's maxHeader.
        let payload = vec![b'x'; MAX_FRAME_BYTES as usize];
        let mut out = Vec::new();
        write_frame(&mut out, &payload).unwrap();
        assert_eq!(&out[..4], &[1, 0, 0, 0]);
        assert_eq!(out.len(), 4 + MAX_FRAME_BYTES as usize);

        // One past the cap: refused with the structured code, nothing written.
        let payload = vec![b'x'; MAX_FRAME_BYTES as usize + 1];
        let mut out = Vec::new();
        let err = write_frame(&mut out, &payload).unwrap_err();
        assert!(err.contains("ERR_NATIVE_FRAME_TOO_LARGE"), "{err}");
        assert!(out.is_empty());

        // Round-trip: what write_frame emits, read_frame decodes verbatim.
        let mut out = Vec::new();
        write_frame(&mut out, br#"{"channel":"rpc"}"#).unwrap();
        match read_frame(&mut Cursor::new(out)).unwrap() {
            InboundFrame::Frame(p) => assert_eq!(p, br#"{"channel":"rpc"}"#),
            other => panic!("round-trip failed: {other:?}"),
        }
    }

    #[test]
    fn truncated_streams_error_instead_of_hanging_or_resyncing() {
        // EOF inside the header.
        let mut cursor = Cursor::new(vec![0u8, 0, 1]);
        assert!(read_frame(&mut cursor).is_err());
        // EOF inside a declared payload.
        let mut bytes = vec![0u8, 0, 0, 10];
        bytes.extend_from_slice(b"short");
        assert!(read_frame(&mut Cursor::new(bytes)).is_err());
        // EOF inside an oversized frame being drained.
        let mut bytes = header_bytes(&manifest()["limits"], "overMaxHeader").to_vec();
        bytes.extend_from_slice(&[0u8; 128]);
        assert!(read_frame(&mut Cursor::new(bytes)).is_err());
    }

    // -- layer 3 -----------------------------------------------------------

    const BOUND: &str = "/Users/u/db/app.sqlite";

    fn invoke(method: &str, payload: serde_json::Value) -> String {
        serde_json::json!({
            "channel": "rpc",
            "content": {
                "kind": "invoke",
                "messageId": "rpc_1_123",
                "targetMethod": method,
                "payload": payload
            }
        })
        .to_string()
    }

    #[test]
    fn gate_pins_initialize_database_to_the_bound_path() {
        // The bound path passes…
        let ok = invoke(
            "initializeDatabase",
            serde_json::json!(["app.sqlite", { "path": BOUND, "readOnlyMode": false }]),
        );
        assert!(gate_envelope(&ok, BOUND).is_ok());

        // …any other path is a retarget attempt and is refused.
        for evil in ["/etc/passwd", "/Users/u/db/app.sqlite2", "", "/Users/u/db"] {
            let envelope = invoke(
                "initializeDatabase",
                serde_json::json!(["x", { "path": evil }]),
            );
            let err = gate_envelope(&envelope, BOUND).unwrap_err();
            assert!(err.contains("ERR_NATIVE_PATH_MISMATCH"), "{evil}: {err}");
        }

        // A missing / non-string path, or a malformed payload shape, is
        // refused as unclassifiable — never forwarded for layer 2 to sort out.
        for payload in [
            serde_json::json!(["x", {}]),
            serde_json::json!(["x", { "path": 7 }]),
            serde_json::json!(["x"]),
            serde_json::json!("not-an-array"),
            serde_json::json!(null),
        ] {
            let envelope = invoke("initializeDatabase", payload.clone());
            let err = gate_envelope(&envelope, BOUND).unwrap_err();
            assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "{payload}: {err}");
        }
    }

    #[test]
    fn gate_passes_non_path_methods_and_refuses_everything_unclassifiable() {
        // Non-path methods flow through.
        for method in ["fetchSchema", "ping", "runQuery", "executeReadQuery", "exportDatabase"] {
            let envelope = invoke(method, serde_json::json!([]));
            assert!(gate_envelope(&envelope, BOUND).is_ok(), "{method}");
        }
        // The audited list includes the 1.8 bounded read-query method.
        assert_eq!(KNOWN_METHODS.len(), 38);

        // Unknown methods are refused, not forwarded (drift fails loud).
        let err = gate_envelope(&invoke("openArbitraryFile", serde_json::json!([])), BOUND)
            .unwrap_err();
        assert!(err.contains("ERR_NATIVE_METHOD_UNLISTED"), "{err}");

        // Unparseable / wrong-shape envelopes are refused.
        for bad in [
            "not json at all",
            r#"{"channel":"rpc"}"#,
            r#"{"channel":"other","content":{"kind":"invoke","messageId":1,"targetMethod":"ping"}}"#,
            r#"{"content":{"kind":"invoke","messageId":1,"targetMethod":"ping"}}"#,
            r#"{"channel":"rpc","content":{"kind":"response","messageId":1,"targetMethod":"ping"}}"#,
            r#"{"channel":"rpc","content":{"kind":"invoke","targetMethod":"ping"}}"#,
            r#"{"channel":"rpc","content":{"kind":"invoke","messageId":1.5,"targetMethod":"ping"}}"#,
            r#"{"channel":"rpc","content":{"kind":"invoke","messageId":null,"targetMethod":"ping"}}"#,
            r#"{"channel":"rpc","content":{"kind":"invoke","messageId":9007199254740992,"targetMethod":"ping"}}"#,
            r#"{"channel":"rpc","content":{"kind":"invoke","messageId":1}}"#,
        ] {
            assert!(gate_envelope(bad, BOUND).is_err(), "must refuse: {bad}");
        }

        // Envelopes over the outbound cap are refused before parsing.
        let huge = format!(
            r#"{{"channel":"rpc","content":{{"kind":"invoke","messageId":1,"targetMethod":"ping","payload":["{}"]}}}}"#,
            "x".repeat(MAX_FRAME_BYTES as usize)
        );
        let err = gate_envelope(&huge, BOUND).unwrap_err();
        assert!(err.contains("ERR_NATIVE_FRAME_TOO_LARGE"), "{err}");
    }

    /// An invoke envelope with `fields` set on its content beside the basics.
    fn invoke_with(method: &str, fields: serde_json::Value) -> String {
        let mut content = serde_json::json!({
            "kind": "invoke",
            "messageId": "rpc_1_123",
            "targetMethod": method
        });
        for (key, value) in fields.as_object().expect("fields is an object") {
            content[key] = value.clone();
        }
        serde_json::json!({ "channel": "rpc", "content": content }).to_string()
    }

    #[test]
    fn the_gate_admits_each_native_transfer_op_and_refuses_malformed_ones() {
        use serde_json::json;
        let id64 = format!("{}abcd", "A-z_09".repeat(10));
        for payload in [
            json!(["push", "req_1_1732500000000", 0, 3, 200, "x".repeat(64)]),
            json!(["push", "a", 2, 3, 3, "y"]),
            json!(["pull", "reply_7", 0]),
            json!(["pull", "reply_7", 41]),
            json!(["commit", "reply_7"]),
            json!(["commit", id64]),
        ] {
            let admitted = gate_envelope(&invoke("nativeTransfer", payload.clone()), BOUND);
            assert!(admitted.is_ok(), "{}: {admitted:?}", excerpt(&payload.to_string()));
        }
        // A piece is bounded in UTF-16 units, as the sidecar counts it: the
        // longest one fits one frame at three UTF-8 bytes per unit, and an
        // astral character is two units.
        let at_limit = "\u{20ac}".repeat(MAX_TRANSFER_PIECE_UNITS as usize);
        let envelope = invoke("nativeTransfer", json!(["push", "t", 0, 1, MAX_TRANSFER_PIECE_UNITS, at_limit]));
        assert!(envelope.len() <= MAX_FRAME_BYTES as usize, "the limit piece fits one frame");
        assert!(gate_envelope(&envelope, BOUND).is_ok(), "a piece at the limit");
        // The bound itself, on the wire: a piece led by "~~" travels one unit
        // longer than it decodes, and the wire length is what is bounded.
        let bound = MAX_TRANSFER_PIECE_UNITS as usize;
        let push = |piece: String| invoke("nativeTransfer", json!(["push", "t", 0, 2, 2 * MAX_TRANSFER_PIECE_UNITS, piece]));
        assert_eq!(MAX_TRANSFER_PIECE_UNITS, 5_591_040, "(16 MiB - 4 KiB) / 3, the viewer's TRANSFER_PIECE_UNITS");
        assert!(gate_envelope(&push("a".repeat(bound)), BOUND).is_ok(), "plain text at the bound");
        assert!(gate_envelope(&push(format!("~~{}", "~".repeat(bound - 2))), BOUND).is_ok(), "~ text at the bound on the wire");
        for over in ["a".repeat(bound + 1), format!("~~{}", "~".repeat(bound - 1))] {
            let err = gate_envelope(&push(over), BOUND).unwrap_err();
            assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "one over on the wire: {err}");
        }
        let ascii_over = "x".repeat(MAX_TRANSFER_PIECE_UNITS as usize + 1);
        let astral_over = "\u{1f600}".repeat(MAX_TRANSFER_PIECE_UNITS as usize / 2 + 1);

        for payload in [
            json!(["drop", "t", 0]),
            json!([7, "t"]),
            json!(["commit"]),
            json!(["commit", ""]),
            json!(["commit", "x".repeat(65)]),
            json!(["commit", "../etc"]),
            json!(["commit", "t d"]),
            json!(["commit", 7]),
            json!(["pull", "t", 1.5]),
            json!(["pull", "t", -1]),
            json!(["pull", "t", "1"]),
            json!(["pull", "t", null]),
            json!(["pull", "t", MAX_TRANSFER_UNITS]),
            json!(["push", "t", 0, 1, 1, 7]),
            json!(["push", "t", 0, 1, 0, "x"]),
            json!(["push", "t", 0, 0, 1, "x"]),
            json!(["push", "t", 0, 3, 2, "x"]),
            json!(["push", "t", 3, 3, 9, "x"]),
            json!(["push", "t", 0, 1, MAX_TRANSFER_UNITS + 1, "x"]),
            json!(["push", "t", 0, 1, 1, ""]),
            json!(["push", "t", 0, 1, 1, "xy"]),
            json!(["push", "t", 0, 1, 1.0, "x"]),
            json!(["push", "t", 0, 1, MAX_TRANSFER_PIECE_UNITS + 1, ascii_over]),
            json!(["push", "t", 0, 1, MAX_TRANSFER_UNITS, astral_over]),
            json!(["push", "t", 0, 1, 1, "x", "extra"]),
            json!(["pull", "t", 0, "extra"]),
            json!(["commit", "t", "extra"]),
            json!(["pull", "t"]),
            json!("commit"),
            json!({ "op": "commit", "id": "t" }),
            json!(null),
        ] {
            let err = gate_envelope(&invoke("nativeTransfer", payload.clone()), BOUND).unwrap_err();
            assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "{}: {err}", excerpt(&payload.to_string()));
        }
        let err = gate_envelope(&invoke_with("nativeTransfer", json!({})), BOUND).unwrap_err();
        assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "no payload: {err}");
        // A transport method, not a worker one: the drift pin's list is unchanged.
        assert!(!KNOWN_METHODS.contains(&"nativeTransfer"));
        assert_eq!(KNOWN_METHODS.len(), 38);
    }

    /// Push envelopes encoded by the viewer's page codec itself
    /// (scripts/gen-native-transfer-fixtures.mjs; the manifest records the
    /// codec sources' hashes, and each case's verdict under the
    /// sidecar's own rule). The codec writes one more `~` before a string that
    /// starts with `~`, and a non-finite number as a `~`-tagged string: the gate
    /// bounds a piece by its wire length as the sidecar does, and refuses one that
    /// decodes to anything but text. The pieces are judged at the manifest's small
    /// test bound; the real bound is pinned in
    /// the_gate_admits_each_native_transfer_op_and_refuses_malformed_ones.
    #[test]
    fn transfer_pieces_from_the_real_codec_are_judged_by_the_sidecars_rule() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native-transfer");
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["transferPieceUnits"].as_u64(),
            Some(MAX_TRANSFER_PIECE_UNITS),
            "the gate's bound is the codec's"
        );
        let test_bound = manifest["testPieceUnits"].as_u64().expect("the bound the pieces were written for");
        let cases = manifest["cases"].as_array().unwrap();
        assert!(cases.len() >= 4);
        let mut wrong = Vec::new();
        for case in cases {
            let file = case["file"].as_str().unwrap();
            let envelope: serde_json::Value = serde_json::from_str(&fs::read_to_string(dir.join(file)).unwrap()).unwrap();
            let verdict = check_native_transfer_bounded(envelope.pointer("/content/payload"), test_bound);
            let right = match case["gate"].as_str().unwrap() {
                "admit" => verdict.is_ok(),
                "refuse" => verdict.as_ref().is_err_and(|e| e.contains("ERR_NATIVE_ENVELOPE_MALFORMED")),
                other => panic!("{file}: unknown expectation {other}"),
            };
            if !right {
                wrong.push(format!("{file} (expected {}): {}", case["gate"], excerpt(&format!("{verdict:?}"))));
            }
            // Through the whole gate at the real bound, every piece here is short;
            // only one that decodes to anything but text is refused.
            let through_gate = gate_envelope(&envelope.to_string(), BOUND);
            if through_gate.is_ok() != (case["decodedType"] == "string") {
                wrong.push(format!("{file} through the gate: {}", excerpt(&format!("{through_gate:?}"))));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");

        // Hand-made wire forms the codec never writes for text: the gate is
        // stricter than the sidecar here, which decodes "~x" as itself.
        let push = |piece: &str| invoke("nativeTransfer", serde_json::json!(["push", "t", 0, 1, 2, piece]));
        assert!(gate_envelope(&push("~~"), BOUND).is_ok(), "the codec's form of a lone ~");
        for tagged in ["~", "~x", "~sqlite-explorer-non-finite:Infinity"] {
            let err = gate_envelope(&push(tagged), BOUND).unwrap_err();
            assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "{tagged}: {err}");
        }
    }

    #[test]
    fn the_gate_takes_a_payload_in_pieces_only_where_the_sidecar_assembles_one() {
        use serde_json::json;
        let transfer = json!({ "id": "req_3_1732500000000", "length": 20_000_000, "parts": 4 });
        for method in [
            "updateCellBatch",
            "deleteRows",
            "insertRowWithHistory",
            "importRows",
            "undoModification",
            "redoModification",
        ] {
            let admitted = gate_envelope(&invoke_with(method, json!({ "payloadTransfer": transfer })), BOUND);
            assert!(admitted.is_ok(), "{method}: {admitted:?}");
        }

        // initializeDatabase, explicitly, even beside a payload the path check
        // would pass: the gate reads its path and deadline from the payload.
        for fields in [
            json!({ "payload": ["x", { "path": BOUND }], "payloadTransfer": transfer }),
            json!({ "payloadTransfer": transfer }),
        ] {
            let err = gate_envelope(&invoke_with("initializeDatabase", fields), BOUND).unwrap_err();
            assert!(
                err.contains("ERR_NATIVE_ENVELOPE_MALFORMED") && err.contains("initializeDatabase cannot take its payload in pieces"),
                "{err}"
            );
        }
        // Any other method, a worker one or the transport itself.
        for method in ["runQuery", "updateCell", "executeReadQuery", "exportTable", "nativeTransfer"] {
            let err = gate_envelope(&invoke_with(method, json!({ "payloadTransfer": transfer })), BOUND).unwrap_err();
            assert!(
                err.contains("ERR_NATIVE_ENVELOPE_MALFORMED") && err.contains("cannot take its payload in pieces"),
                "{method}: {err}"
            );
        }
        // The lists agree with each other: every request-transfer method is an
        // audited worker method, initializeDatabase is never one, and no
        // transport method hides in the worker list.
        assert!(REQUEST_TRANSFER_METHODS.iter().all(|m| KNOWN_METHODS.contains(m)));
        assert!(!REQUEST_TRANSFER_METHODS.contains(&"initializeDatabase"));
        assert!(TRANSPORT_METHODS.iter().all(|m| !KNOWN_METHODS.contains(m)));
        // Never both, so nothing is ambiguous about which one runs.
        for payload in [json!([]), json!(null)] {
            let fields = json!({ "payload": payload, "payloadTransfer": transfer });
            let err = gate_envelope(&invoke_with("updateCellBatch", fields), BOUND).unwrap_err();
            assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED") && err.contains("never both"), "{err}");
        }
        // The transfer's own shape.
        for bad in [
            json!(null),
            json!([]),
            json!("req_1"),
            json!({ "id": "t", "length": 1 }),
            json!({ "id": "t", "length": 1, "parts": 1, "extra": 0 }),
            json!({ "id": "", "length": 1, "parts": 1 }),
            json!({ "id": "a/b", "length": 1, "parts": 1 }),
            json!({ "id": 7, "length": 1, "parts": 1 }),
            json!({ "id": "t", "length": 0, "parts": 1 }),
            json!({ "id": "t", "length": 5, "parts": 0 }),
            json!({ "id": "t", "length": 5, "parts": 6 }),
            json!({ "id": "t", "length": MAX_TRANSFER_UNITS + 1, "parts": 1 }),
            json!({ "id": "t", "length": 1.5, "parts": 1 }),
            json!({ "id": "t", "length": "5", "parts": 1 }),
        ] {
            let fields = json!({ "payloadTransfer": bad });
            let err = gate_envelope(&invoke_with("deleteRows", fields), BOUND).unwrap_err();
            assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "{bad}: {err}");
        }
    }

    #[test]
    fn message_keys_normalise_ints_and_strings_and_refuse_floats() {
        assert_eq!(
            message_key_of(&serde_json::json!("rpc_9")),
            Some(MessageKey::Str("rpc_9".into()))
        );
        assert_eq!(message_key_of(&serde_json::json!(7)), Some(MessageKey::UInt(7)));
        assert_eq!(message_key_of(&serde_json::json!(-3)), Some(MessageKey::Int(-3)));
        assert_eq!(message_key_of(&serde_json::json!(1.5)), None);
        assert_eq!(message_key_of(&serde_json::json!(null)), None);
        assert_eq!(message_key_of(&serde_json::json!({})), None);

        // JS safe-integer boundary: beyond ±(2^53 − 1) the sidecar's echo
        // rounds through JS number semantics and the response could never
        // route back — accepting the id would strand its own request.
        assert_eq!(
            message_key_of(&serde_json::json!(9_007_199_254_740_991u64)),
            Some(MessageKey::UInt(JS_MAX_SAFE_INTEGER))
        );
        assert_eq!(message_key_of(&serde_json::json!(9_007_199_254_740_992u64)), None);
        assert_eq!(message_key_of(&serde_json::json!(u64::MAX)), None);
        assert_eq!(
            message_key_of(&serde_json::json!(-9_007_199_254_740_991i64)),
            Some(MessageKey::Int(-(JS_MAX_SAFE_INTEGER as i64)))
        );
        assert_eq!(message_key_of(&serde_json::json!(-9_007_199_254_740_992i64)), None);
        assert_eq!(message_key_of(&serde_json::json!(i64::MIN)), None);
    }

    // -- routing + crash fanout --------------------------------------------

    fn core_with_pending(ids: &[&str]) -> (Arc<SidecarCore>, Vec<mpsc::Receiver<RpcOutcome>>) {
        // No writer queue: these tests never write frames (submit against a
        // taken writer_tx is itself one of the covered failure paths).
        let core = Arc::new(SidecarCore {
            bound_path: BOUND.to_string(),
            identity: None,
            pending: Mutex::new(HashMap::new()),
            writer_tx: Mutex::new(None),
            dead: Mutex::new(None),
        });
        let mut receivers = Vec::new();
        for id in ids {
            let (tx, rx) = mpsc::channel();
            core.pending
                .lock()
                .unwrap()
                .insert(MessageKey::Str(id.to_string()), Responder::Blocking(tx));
            receivers.push(rx);
        }
        (core, receivers)
    }

    fn response_frame(message_id: &str) -> Vec<u8> {
        let payload = serde_json::json!({
            "channel": "rpc",
            "content": { "kind": "response", "messageId": message_id, "success": true, "data": true }
        })
        .to_string();
        let mut out = Vec::new();
        write_frame(&mut out, payload.as_bytes()).unwrap();
        out
    }

    /// Simulated sidecar death: one routed response, then EOF. The routed
    /// request resolves with the verbatim payload; every OTHER pending
    /// request is fanned out with a structured error — none hang.
    #[test]
    fn crash_fanout_resolves_every_pending_request() {
        let (core, receivers) = core_with_pending(&["a", "b", "c"]);
        let mut stream = Cursor::new(response_frame("a"));
        assert_eq!(pump_frames(&mut stream, &core), LoopEnd::Eof);
        core.fail_all("ERR_NATIVE_SIDECAR_EXITED: the native sidecar closed its pipe (exit code 1)");

        let a = receivers[0].try_recv().expect("a resolved").expect("a ok");
        assert!(a.contains("\"messageId\":\"a\""), "verbatim payload: {a}");
        for rx in &receivers[1..] {
            let err = rx.try_recv().expect("resolved, not hung").unwrap_err();
            assert!(err.contains("ERR_NATIVE_SIDECAR_EXITED"), "{err}");
        }
        assert!(core.pending.lock().unwrap().is_empty());

        // After death the core refuses new submissions with the same reason.
        let err = core
            .submit(MessageKey::Str("late".into()), "{}")
            .unwrap_err();
        assert!(err.contains("ERR_NATIVE_SIDECAR_EXITED"), "{err}");
    }

    /// A desync mid-stream stops the loop dead: the well-formed frame queued
    /// BEHIND the garbage header must not be delivered (the anti-regression
    /// for the eat-everything/keep-going class), and fanout resolves its
    /// pending entry with an error instead.
    #[test]
    fn desync_stops_routing_and_fanout_covers_the_rest() {
        let (core, receivers) = core_with_pending(&["x"]);
        let mut bytes = 0x8000_0000u32.to_be_bytes().to_vec(); // the signed trap
        bytes.extend_from_slice(&response_frame("x"));
        let end = pump_frames(&mut Cursor::new(bytes), &core);
        assert_eq!(end, LoopEnd::Desync { declared: 0x8000_0000 });
        assert!(
            receivers[0].try_recv().is_err(),
            "the frame behind the desync must NOT have been delivered"
        );
        core.fail_all("ERR_NATIVE_FRAME_DESYNC: unrecoverable");
        let err = receivers[0].try_recv().unwrap().unwrap_err();
        assert!(err.contains("ERR_NATIVE_FRAME_DESYNC"), "{err}");
    }

    /// Unroutable frames — messageId null (the sidecar's transport-level
    /// error frames), an unknown id, or garbage — are logged and skipped;
    /// they neither crash the loop nor consume anyone's pending entry.
    #[test]
    fn unroutable_frames_are_logged_not_fatal() {
        let (core, receivers) = core_with_pending(&["keep"]);
        let mut stream = Vec::new();
        let null_id = serde_json::json!({
            "channel": "rpc",
            "content": { "kind": "response", "messageId": null, "success": false,
                          "error": { "code": "ERR_NATIVE_FRAME_TOO_LARGE" } }
        })
        .to_string();
        write_frame(&mut stream, null_id.as_bytes()).unwrap();
        write_frame(&mut stream, b"not json").unwrap();
        stream.extend_from_slice(&response_frame("nobody-waits-for-this"));
        stream.extend_from_slice(&response_frame("keep"));
        assert_eq!(pump_frames(&mut Cursor::new(stream), &core), LoopEnd::Eof);
        let kept = receivers[0].try_recv().expect("still routed").expect("ok");
        assert!(kept.contains("\"messageId\":\"keep\""));
    }

    #[test]
    fn duplicate_message_ids_are_refused_without_orphaning_the_first() {
        let (core, receivers) = core_with_pending(&["dup"]);
        let err = core
            .submit(MessageKey::Str("dup".into()), "{}")
            .unwrap_err();
        assert!(err.contains("ERR_NATIVE_DUPLICATE_MESSAGE_ID"), "{err}");
        // The first caller's entry is still live and still resolvable.
        let mut stream = Cursor::new(response_frame("dup"));
        pump_frames(&mut stream, &core);
        assert!(receivers[0].try_recv().unwrap().is_ok());
    }

    /// The reviewer's long-query-plus-big-envelope attack, end to end: a
    /// child that never reads stdin wedges the writer thread inside a
    /// `write_all` once the ~64 KiB pipe buffer fills. Both review
    /// properties must hold: (a) shutdown completes within the force-kill
    /// window without the writer's cooperation, and (b) no `submit` call
    /// ever parks on pipe state — the bounded queue pushes back fast.
    #[cfg(unix)]
    #[test]
    fn wedged_writer_never_parks_submit_and_shutdown_stays_bounded() {
        let child = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn a stdin-ignoring child");
        let (core, child) = wire_child(child, BOUND, None).expect("wire");

        // 256 KiB frames: the first wedges the writer against the full pipe,
        // the queue absorbs up to WRITE_QUEUE_CAP more, then try_send fails.
        let big = "x".repeat(256 * 1024);
        let mut receivers = Vec::new();
        let mut backpressure_seen = false;
        for i in 0..(WRITE_QUEUE_CAP + 4) as u64 {
            let started = Instant::now();
            match core.submit(MessageKey::UInt(i), &big) {
                Ok(rx) => receivers.push(rx),
                Err(e) => {
                    assert!(e.contains("ERR_NATIVE_WRITE_BACKPRESSURE"), "{e}");
                    backpressure_seen = true;
                }
            }
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "submit #{i} parked on a wedged pipe"
            );
            // Give the writer a beat to pick up the first frame and wedge.
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(backpressure_seen, "the bounded queue never pushed back");

        // Shutdown with the writer wedged mid-write: bounded by grace +
        // SIGKILL (which collapses the pipe and unblocks the writer), never
        // by the writer volunteering. This is the exact path RunEvent::Exit
        // runs on the main thread.
        let handle = SidecarHandle::unclaimed(Arc::clone(&core), Arc::clone(&child));
        let started = Instant::now();
        shutdown_handle(handle, "ERR_NATIVE_SIDECAR_EXITED: closed by native_close");
        let elapsed = started.elapsed();
        assert!(
            elapsed < SHUTDOWN_WAIT + Duration::from_secs(2),
            "shutdown took {elapsed:?} — the force-kill guarantee is broken"
        );
        // Crash-fanout intact: every accepted request resolved, none hang.
        for (i, rx) in receivers.iter().enumerate() {
            let outcome = rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_else(|_| panic!("pending #{i} hung"));
            let err = outcome.expect_err("no response can exist");
            assert!(err.contains("ERR_NATIVE_SIDECAR_EXITED"), "{err}");
        }
        // Reaped, not zombied (status cached by the shutdown's wait).
        assert!(child.lock().unwrap().try_wait().expect("wait").is_some());
    }

    /// The hostile half-close interleave: the child closes ONLY its stdin
    /// read end (`exec 0<&-`) but keeps stdout open and stays alive, so the
    /// next write EPIPEs while the reader never sees an EOF — the reader-side
    /// fanout can never fire. The WRITER must total the fanout itself: every
    /// accepted request resolves with a structured error, with NO close call.
    #[cfg(unix)]
    #[test]
    fn writer_pipe_error_with_live_child_fails_all_pending() {
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec 0<&-; sleep 60")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn a half-closing child");
        // Let the shell's `exec 0<&-` land first: a frame written BEFORE the
        // close would sit in the pipe buffer without an EPIPE and defeat the
        // interleave this test exists to pin.
        std::thread::sleep(Duration::from_millis(300));
        let (core, child) = wire_child(child, BOUND, None).expect("wire");

        let mut receivers = Vec::new();
        for i in 0..3u64 {
            match core.submit(MessageKey::UInt(i), r#"{"probe":true}"#) {
                Ok(rx) => receivers.push(rx),
                // A submit that lands after the writer's fanout is refused
                // with the recorded reason — also a resolution, not a park.
                Err(e) => assert!(e.contains("ERR_NATIVE_SIDECAR_EXITED"), "{e}"),
            }
        }
        assert!(!receivers.is_empty(), "at least one submit must have been accepted");
        for (i, rx) in receivers.iter().enumerate() {
            let outcome = rx
                .recv_timeout(Duration::from_secs(3))
                .unwrap_or_else(|_| panic!("pending #{i} parked — the writer fanout is missing"));
            let err = outcome.expect_err("no response can exist");
            assert!(err.contains("ERR_NATIVE_SIDECAR_EXITED"), "{err}");
        }
        // The fanout came from the WRITER: the child is still alive with its
        // stdout open, so no reader-side EOF can have fired.
        assert!(
            child.lock().unwrap().try_wait().expect("try_wait").is_none(),
            "child died — this run did not exercise the half-close interleave"
        );
        assert!(core.dead.lock().unwrap().is_some());
        // Cleanup without waiting out the 60 s sleep.
        {
            let mut child = child.lock().unwrap();
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    // -- N-sidecar registry: DbId is the routing authority ------------------

    const BOUND_A: &str = "/Users/u/db/alpha.sqlite";
    const BOUND_B: &str = "/Users/u/db/beta.sqlite";

    /// Plays the sidecar for exactly ONE request: takes the frame the shell
    /// enqueued and echoes its messageId back with the ANSWERING core's bound
    /// path as the response data — that path is what proves which sidecar the
    /// envelope actually reached. Hands the queue receiver back so the caller
    /// can go on asserting that nothing further was ever enqueued.
    fn answer_once(
        core: Arc<SidecarCore>,
        rx: mpsc::Receiver<Vec<u8>>,
    ) -> std::thread::JoinHandle<mpsc::Receiver<Vec<u8>>> {
        std::thread::spawn(move || {
            let raw = rx.recv().expect("a frame must be enqueued");
            let env: serde_json::Value = serde_json::from_slice(&raw).expect("envelope parses");
            let reply = serde_json::json!({
                "channel": "rpc",
                "content": {
                    "kind": "response",
                    "messageId": env.pointer("/content/messageId").expect("id").clone(),
                    "success": true,
                    "data": { "answeredBy": core.bound_path }
                }
            })
            .to_string();
            route_payload(&core, reply.into_bytes());
            rx
        })
    }

    /// THE cross-talk test. The dangerous class is the PATH-LESS envelope
    /// (`runQuery`, mutations, undo) — it carries no `config.path`, so before
    /// the DbId existed it passed the gate and ran against whichever sidecar
    /// happened to be "current". Routing must now come from the DbId alone:
    /// DB-A's statement reaches A's sidecar and B's queue stays empty.
    #[test]
    fn an_envelope_for_one_db_never_reaches_another_sidecar() {
        let manager = NativeSidecar::default();
        let (id_a, core_a, rx_a) = fake_entry(&manager, BOUND_A);
        let (id_b, core_b, rx_b) = fake_entry(&manager, BOUND_B);
        assert_ne!(id_a, id_b, "every open gets its own id");

        let responder = answer_once(Arc::clone(&core_a), rx_a);
        let out = rpc_inner(&manager, &id_a, &invoke("runQuery", serde_json::json!(["SELECT 1"])))
            .expect("DB-A's own sidecar answers");
        let rx_a = responder.join().expect("responder thread");
        assert!(out.contains(BOUND_A), "answered by the wrong sidecar: {out}");
        assert!(!out.contains(BOUND_B), "{out}");
        assert!(
            rx_b.try_recv().is_err(),
            "DB-B's sidecar received a frame it was never addressed"
        );
        assert!(core_b.pending.lock().unwrap().is_empty());

        // The mirror image, so neither direction is an accident of ordering.
        let responder = answer_once(Arc::clone(&core_b), rx_b);
        let out = rpc_inner(&manager, &id_b, &invoke("runQuery", serde_json::json!(["SELECT 2"])))
            .expect("DB-B's own sidecar answers");
        let rx_b = responder.join().expect("responder thread");
        assert!(out.contains(BOUND_B) && !out.contains(BOUND_A), "{out}");
        assert!(rx_a.try_recv().is_err(), "DB-A's sidecar received DB-B's traffic");
        assert!(core_a.pending.lock().unwrap().is_empty());
        // Exactly one frame per round trip: each queue is empty again, so no
        // envelope was duplicated onto a second sidecar behind the response.
        assert!(rx_b.try_recv().is_err());

        close_all_inner(&manager, "test over");
    }

    /// Unknown, malformed, and already-closed ids are ONE structured refusal —
    /// deliberately indistinguishable, so the webview learns nothing from the
    /// difference — and never a fallback onto a live sidecar. The DB's own
    /// PATH is in the bogus set: ids are shell-issued tokens, not paths.
    #[test]
    fn an_unknown_or_closed_db_id_is_refused_and_never_retargets() {
        let manager = NativeSidecar::default();
        let (id_a, core_a, rx_a) = fake_entry(&manager, BOUND_A);
        let envelope = invoke("runQuery", serde_json::json!(["SELECT 1"]));

        for bogus in [
            "",
            "db_",
            "db_999",
            "DB_0",
            " db_0",
            "db_0 ",
            BOUND_A,
            "../db_0",
            "0",
            "db_0\u{0}",
        ] {
            // Resolution first, deliberately: it is the same call the two
            // export commands make, and it fails FAST. A resolver that fell
            // back to another sidecar would make the rpc below hang on a
            // response nobody will send, so the fast assertion is what keeps
            // that regression a clean failure instead of a wedged suite.
            assert!(core_for(&manager, bogus).is_err(), "{bogus:?}");
            let err = rpc_inner(&manager, bogus, &envelope).unwrap_err();
            assert!(err.contains("ERR_NATIVE_UNKNOWN_DB"), "{bogus:?}: {err}");
        }
        assert!(
            rx_a.try_recv().is_err(),
            "a refused id must not have framed anything toward the live sidecar"
        );
        assert!(core_a.pending.lock().unwrap().is_empty());

        // A CLOSED id is refused the same way — the survivor does not inherit
        // the closed database's traffic.
        let (id_b, _core_b, rx_b) = fake_entry(&manager, BOUND_B);
        close_inner(&manager, &id_a, "closed by test").expect("close the live id");
        assert!(core_for(&manager, &id_a).is_err(), "a closed id must not resolve");
        let err = rpc_inner(&manager, &id_a, &envelope).unwrap_err();
        assert!(err.contains("ERR_NATIVE_UNKNOWN_DB"), "{err}");
        assert!(
            rx_b.try_recv().is_err(),
            "the surviving sidecar received the closed database's traffic"
        );

        // Closing twice, or closing an id that never existed, closes NOBODY.
        assert!(close_inner(&manager, &id_a, "again").is_err());
        assert!(close_inner(&manager, "db_nope", "nobody").is_err());
        assert!(open_ids(&manager).contains(&id_b));
        close_all_inner(&manager, "test over");
    }

    /// Layer 3's path check is unchanged — but it is now evaluated against the
    /// bound path of the sidecar the DbId resolved to, so an envelope
    /// submitted for DB-A that names DB-B's file is a retarget attempt.
    #[test]
    fn path_authority_is_evaluated_against_the_id_resolved_sidecar() {
        let manager = NativeSidecar::default();
        let (id_a, core_a, rx_a) = fake_entry(&manager, BOUND_A);
        let (id_b, core_b, rx_b) = fake_entry(&manager, BOUND_B);
        let cross = invoke(
            "initializeDatabase",
            serde_json::json!(["beta", { "path": BOUND_B, "readOnlyMode": false }]),
        );

        let err = rpc_inner(&manager, &id_a, &cross).unwrap_err();
        assert!(err.contains("ERR_NATIVE_PATH_MISMATCH"), "{err}");
        assert!(
            rx_a.try_recv().is_err() && rx_b.try_recv().is_err(),
            "a refused envelope must never be framed toward any sidecar"
        );
        assert!(core_a.pending.lock().unwrap().is_empty());
        assert!(core_b.pending.lock().unwrap().is_empty());

        // The very same envelope under B's own id passes and reaches B.
        let responder = answer_once(Arc::clone(&core_b), rx_b);
        let out = rpc_inner(&manager, &id_b, &cross).expect("B may open B");
        let rx_b = responder.join().expect("responder thread");
        assert!(out.contains(BOUND_B), "{out}");
        assert!(rx_a.try_recv().is_err() && rx_b.try_recv().is_err());
        close_all_inner(&manager, "test over");
    }

    /// Closing one database shuts down exactly its sidecar: its in-flight
    /// requests are fanned out (never hung), and every other database keeps
    /// serving a full round trip.
    #[test]
    fn closing_one_db_leaves_the_others_serving() {
        let manager = NativeSidecar::default();
        let (id_a, core_a, _rx_a) = fake_entry(&manager, BOUND_A);
        let (id_b, core_b, rx_b) = fake_entry(&manager, BOUND_B);

        let inflight = core_a
            .submit(MessageKey::Str("inflight".into()), r#"{"probe":1}"#)
            .expect("submit against the live sidecar");
        close_inner(&manager, &id_a, "ERR_NATIVE_SIDECAR_EXITED: closed by native_close")
            .expect("close A");
        let err = inflight
            .recv_timeout(Duration::from_secs(2))
            .expect("A's pending request must be fanned out, not hung")
            .unwrap_err();
        assert!(err.contains("ERR_NATIVE_SIDECAR_EXITED"), "{err}");
        assert!(core_a.dead.lock().unwrap().is_some());

        assert!(core_b.dead.lock().unwrap().is_none(), "B must be untouched");
        let responder = answer_once(Arc::clone(&core_b), rx_b);
        let out = rpc_inner(&manager, &id_b, &invoke("fetchSchema", serde_json::json!([])))
            .expect("B still serves");
        responder.join().expect("responder thread");
        assert!(out.contains(BOUND_B), "{out}");
        assert_eq!(open_ids(&manager).len(), 1);
        close_all_inner(&manager, "test over");
    }

    /// App exit closes EVERY sidecar, each under the same bounded grace +
    /// force-kill discipline the single-sidecar shutdown had — and the
    /// AGGREGATE cost is one grace period, not N of them. THREE children that
    /// ignore stdin EOF entirely are the discriminator: reaped serially they
    /// would cost 3 × SHUTDOWN_WAIT (and 16 tabs of them would freeze the
    /// quit for half a minute); reaped concurrently the grace periods overlap.
    #[cfg(unix)]
    #[test]
    fn exit_closes_every_sidecar_within_one_aggregate_grace_period() {
        let manager = NativeSidecar::default();
        let (_id_a, core_a, _rx_a) = fake_entry(&manager, BOUND_A);
        let (_id_b, core_b, _rx_b) = fake_entry(&manager, BOUND_B);

        let mut stubborn = Vec::new();
        for i in 0..3 {
            let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE_CAP);
            let core = Arc::new(SidecarCore::new(format!("/Users/u/db/stubborn-{i}.sqlite"), None, tx));
            let child = Arc::new(Mutex::new(
                Command::new("/bin/sleep")
                    .arg("30")
                    .spawn()
                    .expect("spawn a stubborn child"),
            ));
            register_sidecar(
                &manager,
                SidecarHandle::unclaimed(Arc::clone(&core), Arc::clone(&child)),
            )
            .expect("register");
            stubborn.push((core, child, rx));
        }
        assert_eq!(open_ids(&manager).len(), 5);

        let started = Instant::now();
        close_all_inner(&manager, "ERR_NATIVE_SIDECAR_EXITED: the application is exiting");
        let elapsed = started.elapsed();

        assert!(open_ids(&manager).is_empty(), "registry must be empty");
        let all_cores: Vec<&Arc<SidecarCore>> = [&core_a, &core_b]
            .into_iter()
            .chain(stubborn.iter().map(|(core, _, _)| core))
            .collect();
        for (i, core) in all_cores.iter().enumerate() {
            let dead = core.dead.lock().unwrap();
            let reason = dead.as_ref().unwrap_or_else(|| panic!("sidecar #{i} not failed out"));
            assert!(reason.contains("the application is exiting"), "{reason}");
        }
        for (i, (_core, child, _rx)) in stubborn.iter().enumerate() {
            assert!(
                child.lock().unwrap().try_wait().expect("wait").is_some(),
                "stubborn child #{i} was not reaped"
            );
        }
        // ONE grace period plus slack — NOT 3 × SHUTDOWN_WAIT, which is what a
        // serial close-all costs and what this bound exists to forbid.
        assert!(
            elapsed < SHUTDOWN_WAIT + Duration::from_secs(2),
            "close-all took {elapsed:?} — the reaps are not overlapping (serial would be {:?})",
            SHUTDOWN_WAIT * 3
        );
    }

    /// The orphan backstop that ADD semantics removed: a page-generation
    /// change (reload, devtools reload, navigation, content-process restart)
    /// throws away every DbId the host held, so nothing could ever close those
    /// sidecars again. The shell reaps them itself when the old page goes.
    #[test]
    fn a_page_reload_reaps_the_sidecars_no_page_can_name_any_more() {
        let manager = NativeSidecar::default();
        let (id_a, core_a, _rx_a) = fake_entry(&manager, BOUND_A);
        let (_id_b, core_b, _rx_b) = fake_entry(&manager, BOUND_B);

        let reaper =
            reap_orphaned_sidecars(&manager, "reloaded").expect("there was something to reap");
        // The DRAIN is synchronous: the registry is already empty when the new
        // page's first script runs, so no stale id can be addressed even while
        // the reaping is still in flight.
        assert!(open_ids(&manager).is_empty());
        let err = rpc_inner(&manager, &id_a, &invoke("runQuery", serde_json::json!(["SELECT 1"])))
            .unwrap_err();
        assert!(err.contains("ERR_NATIVE_UNKNOWN_DB"), "{err}");

        // The REAPING is detached — this join belongs to the test; the call
        // site drops the handle on purpose.
        reaper.join().expect("reaper thread");
        for (i, core) in [&core_a, &core_b].iter().enumerate() {
            assert!(core.dead.lock().unwrap().is_some(), "sidecar #{i} was not reaped");
        }

        // A reload is not a shutdown: the registry stays usable for the new page.
        let (id_c, _core_c, _rx_c) = fake_entry(&manager, BOUND_A);
        assert!(core_for(&manager, &id_c).is_ok());
        close_all_inner(&manager, "test over");

        // First load has nothing to reap — the common case is a no-op.
        assert!(reap_orphaned_sidecars(&NativeSidecar::default(), "first load").is_none());
    }

    /// The terminal drain latches the registry shut, so an open that was
    /// already past it — `native_open` holds `open_serial` across a spawn and
    /// a ≤10 s handshake — cannot insert a live child into the emptied map at
    /// app exit, where nothing would be left to reap it.
    #[cfg(unix)]
    #[test]
    fn a_terminal_close_all_latches_the_registry_shut() {
        let manager = NativeSidecar::default();
        let (_id, _core, _rx) = fake_entry(&manager, BOUND_A);
        close_all_inner(&manager, "ERR_NATIVE_SIDECAR_EXITED: the application is exiting");
        assert!(open_ids(&manager).is_empty());

        let err = assert_capacity(&manager).unwrap_err();
        assert!(err.contains("ERR_NATIVE_SHUTTING_DOWN"), "{err}");

        // A sidecar that finished launching after the drain: refused AND
        // reaped, never inserted and never dropped-while-alive.
        let (tx, _rx) = mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE_CAP);
        let core = Arc::new(SidecarCore::new(BOUND_B.to_string(), None, tx));
        let child = Arc::new(Mutex::new(
            Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .expect("spawn a late child"),
        ));
        let err = register_sidecar(
            &manager,
            SidecarHandle::unclaimed(Arc::clone(&core), Arc::clone(&child)),
        )
        .unwrap_err();
        assert!(err.contains("ERR_NATIVE_SHUTTING_DOWN"), "{err}");
        assert!(open_ids(&manager).is_empty(), "nothing may enter a latched registry");
        assert!(core.dead.lock().unwrap().is_some());
        assert!(
            child.lock().unwrap().try_wait().expect("wait").is_some(),
            "the late child must be reaped, not leaked"
        );
    }

    /// The registry cannot be grown without bound. A compromised webview can
    /// re-open an ALREADY-allowlisted path as often as it likes, and each open
    /// is a process — the replace-the-one-sidecar semantics used to bound that
    /// implicitly, so the cap replaces the bound the registry removes.
    #[test]
    fn the_registry_refuses_to_grow_past_the_open_cap() {
        let manager = NativeSidecar::default();
        let mut entries = Vec::new();
        for _ in 0..MAX_NATIVE_SIDECARS {
            entries.push(fake_entry(&manager, BOUND_A));
        }
        assert_eq!(open_ids(&manager).len(), MAX_NATIVE_SIDECARS);

        // `open_inner` checks this BEFORE spawning, so a refusal never leaves
        // a child to reap…
        let err = assert_capacity(&manager).unwrap_err();
        assert!(err.contains("ERR_NATIVE_TOO_MANY_DATABASES"), "{err}");

        // …and the registration itself re-checks and shuts the handle down
        // rather than leaking a live child if one ever got that far.
        let (tx, _rx) = mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE_CAP);
        let core = Arc::new(SidecarCore::new(BOUND_B.to_string(), None, tx));
        let child = Arc::new(Mutex::new(placeholder_child()));
        let err = register_sidecar(
            &manager,
            SidecarHandle::unclaimed(Arc::clone(&core), Arc::clone(&child)),
        )
        .unwrap_err();
        assert!(err.contains("ERR_NATIVE_TOO_MANY_DATABASES"), "{err}");
        assert!(core.dead.lock().unwrap().is_some(), "the refused handle must be shut down");
        assert!(child.lock().unwrap().try_wait().expect("wait").is_some());
        assert_eq!(open_ids(&manager).len(), MAX_NATIVE_SIDECARS);
        close_all_inner(&manager, "test over");
    }

    /// DbIds are opaque shell-issued tokens: monotonic, unique, and never
    /// derived from the database's path — the same file opened twice is two
    /// independent entries with two different ids.
    #[test]
    fn db_ids_are_opaque_shell_issued_tokens() {
        let first = next_db_id();
        let second = next_db_id();
        assert_ne!(first, second);
        for id in [&first, &second] {
            assert!(id.starts_with("db_"), "{id}");
            assert!(
                id["db_".len()..].chars().all(|c| c.is_ascii_digit()),
                "{id} must be a bare counter token"
            );
        }

        let manager = NativeSidecar::default();
        let (id1, _c1, _rx1) = fake_entry(&manager, BOUND_A);
        let (id2, _c2, _rx2) = fake_entry(&manager, BOUND_A);
        assert_ne!(id1, id2, "the same path twice must not collide onto one entry");
        assert!(!id1.contains(BOUND_A) && !id2.contains(BOUND_A));
        assert_eq!(open_ids(&manager).len(), 2);
        close_all_inner(&manager, "test over");
    }

    /// Single-database behaviour is unchanged with exactly one entry: the
    /// round trip works, and the id the shell issued is the only one that
    /// reaches it (there is no implicit "the current sidecar" any more).
    #[test]
    fn one_open_database_behaves_exactly_as_before() {
        let manager = NativeSidecar::default();
        let (id, core, rx) = fake_entry(&manager, BOUND_A);
        assert_eq!(open_ids(&manager).len(), 1);

        let responder = answer_once(Arc::clone(&core), rx);
        let out = rpc_inner(&manager, &id, &invoke("fetchSchema", serde_json::json!([])))
            .expect("the single sidecar answers");
        let rx = responder.join().expect("responder thread");
        assert!(out.contains(BOUND_A), "{out}");

        // Layer 3 still pins initializeDatabase to that sidecar's bound path.
        let err = rpc_inner(
            &manager,
            &id,
            &invoke("initializeDatabase", serde_json::json!(["x", { "path": "/etc/passwd" }])),
        )
        .unwrap_err();
        assert!(err.contains("ERR_NATIVE_PATH_MISMATCH"), "{err}");
        assert!(rx.try_recv().is_err());

        close_all_inner(&manager, "test over");
        assert!(open_ids(&manager).is_empty());
        assert!(core.dead.lock().unwrap().is_some());
    }

    // -- layer 1 -----------------------------------------------------------

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sqx-native-test-{}-{tag}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn layer1_refuses_paths_the_user_never_picked() {
        let allowlist = crate::SessionAllowlist::default();
        let err = resolve_bound_path(&allowlist, Path::new("/etc/passwd")).unwrap_err();
        assert!(err.contains("ERR_NATIVE_PATH_NOT_ALLOWED"), "{err}");
        assert!(err.contains("not allowlisted"), "{err}");
    }

    #[test]
    fn layer1_binds_allowlisted_paths_to_their_canonical_form() {
        let dir = scratch("layer1-ok");
        let db = dir.join("picked.db");
        fs::write(&db, b"").unwrap();
        let allowlist = crate::SessionAllowlist::default();
        crate::allowlist_insert_for_tests(&allowlist, db.clone());
        let bound = resolve_bound_path(&allowlist, &db).unwrap();
        assert_eq!(bound, fs::canonicalize(&db).unwrap());
        // std::env::temp_dir on macOS goes through /var → /private/var, so
        // this genuinely exercises directory-level canonicalisation.
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A final-component symlink must be refused even when its PATH is
    /// allowlisted: an rw sidecar would write through it to a file the user
    /// never picked, which the shell's own save path never does.
    #[cfg(unix)]
    #[test]
    fn layer1_refuses_a_final_component_symlink() {
        use std::os::unix::fs::symlink;
        let dir = scratch("layer1-symlink");
        let victim = dir.join("victim.db");
        fs::write(&victim, b"").unwrap();
        let link = dir.join("innocent.db");
        symlink(&victim, &link).unwrap();
        let allowlist = crate::SessionAllowlist::default();
        crate::allowlist_insert_for_tests(&allowlist, link.clone());
        let err = resolve_bound_path(&allowlist, &link).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        fs::remove_dir_all(&dir).unwrap();
    }

    // -- file identity: external replacement --------------------------------

    /// The whole point of comparing device+inode and NOTHING else: an ordinary
    /// external write (DML, a checkpoint, VACUUM) keeps the inode, so it must
    /// not retire the connection; a rename over the path or a delete must.
    #[test]
    fn file_identity_survives_in_place_writes_and_catches_replacement() {
        use std::io::Write;
        let dir = scratch("identity");
        let db = dir.join("live.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let opened = FileIdentity::of(&db).unwrap();

        // In-place growth: size and mtime move, the identity does not.
        let mut file = fs::OpenOptions::new().append(true).open(&db).unwrap();
        file.write_all(&[0u8; 4096]).unwrap();
        drop(file);
        assert_eq!(FileIdentity::of(&db).unwrap(), opened);

        // An atomic rename over the path is a different file.
        let replacement = dir.join("replacement.db");
        fs::write(&replacement, b"SQLite format 3\0other").unwrap();
        fs::rename(&replacement, &db).unwrap();
        assert_ne!(FileIdentity::of(&db).unwrap(), opened);

        // Deleted: no identity at all, never a match.
        fs::remove_file(&db).unwrap();
        assert!(FileIdentity::of(&db).is_err());
        // A directory planted at the path is refused as not-a-file.
        fs::create_dir(&db).unwrap();
        assert!(FileIdentity::of(&db).unwrap_err().contains("not a regular file"));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The gate itself: a pinned sidecar keeps answering across an in-place
    /// write, and is refused — BEFORE its queue sees the envelope — once the
    /// file at its bound path is a different inode. The refusal is the
    /// structured `ERR_NATIVE_FILE_CHANGED` the page retires on.
    #[test]
    fn a_replaced_file_is_refused_before_the_sidecar_sees_the_envelope() {
        use std::io::Write;
        let dir = scratch("identity-gate");
        let db = dir.join("bound.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let bound = fs::canonicalize(&db).unwrap();
        let bound_str = bound.to_str().unwrap().to_string();
        let manager = NativeSidecar::default();
        let (id, core, rx) =
            try_fake_entry_pinned(&manager, &bound_str, FileIdentity::of(&bound).unwrap())
                .expect("register");

        // Ordinary external write: still the same file, still answered.
        let mut file = fs::OpenOptions::new().append(true).open(&bound).unwrap();
        file.write_all(&[0u8; 512]).unwrap();
        drop(file);
        let responder = answer_once(Arc::clone(&core), rx);
        let out = rpc_inner(&manager, &id, &invoke("runQuery", serde_json::json!(["SELECT 1"])))
            .expect("an in-place write is not a replacement");
        let rx = responder.join().expect("responder thread");
        let response: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(response["content"]["data"]["answeredBy"], bound_str);

        // Replacement: refused at the gate, nothing enqueued, nothing pending.
        let replacement = dir.join("replacement.db");
        fs::write(&replacement, b"SQLite format 3\0other").unwrap();
        fs::rename(&replacement, &bound).unwrap();
        let err = rpc_inner(&manager, &id, &invoke("runQuery", serde_json::json!(["COMMIT"])))
            .unwrap_err();
        assert!(err.starts_with("ERR_NATIVE_FILE_CHANGED:"), "{err}");
        assert!(err.contains("replaced, moved, or deleted"), "{err}");
        assert!(rx.try_recv().is_err(), "the refused envelope must never reach the sidecar");
        assert!(core.pending.lock().unwrap().is_empty());

        // Deleted: same refusal, naming the stat failure.
        fs::remove_file(&bound).unwrap();
        let err = rpc_inner(&manager, &id, &invoke("fetchSchema", serde_json::json!([])))
            .unwrap_err();
        assert!(err.starts_with("ERR_NATIVE_FILE_CHANGED:"), "{err}");
        assert!(rx.try_recv().is_err());

        close_all_inner(&manager, "test over");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A replacement that lands WHILE the sidecar is executing is reported
    /// instead of the sidecar's answer: the post-check makes the refusal win
    /// over a stale success (a COMMIT that went to the orphaned inode).
    #[test]
    fn a_replacement_during_the_statement_fails_the_answer() {
        let dir = scratch("identity-post");
        let db = dir.join("bound.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let bound = fs::canonicalize(&db).unwrap();
        let bound_str = bound.to_str().unwrap().to_string();
        let manager = NativeSidecar::default();
        let (id, core, rx) =
            try_fake_entry_pinned(&manager, &bound_str, FileIdentity::of(&bound).unwrap())
                .expect("register");

        // The responder replaces the file, THEN answers success.
        let replace_then_answer = {
            let core = Arc::clone(&core);
            let bound = bound.clone();
            let replacement = dir.join("replacement.db");
            std::thread::spawn(move || {
                let raw = rx.recv().expect("a frame must be enqueued");
                let env: serde_json::Value = serde_json::from_slice(&raw).expect("envelope parses");
                fs::write(&replacement, b"SQLite format 3\0other").unwrap();
                fs::rename(&replacement, &bound).unwrap();
                let reply = serde_json::json!({
                    "channel": "rpc",
                    "content": {
                        "kind": "response",
                        "messageId": env.pointer("/content/messageId").expect("id").clone(),
                        "success": true,
                        "data": { "committed": true }
                    }
                })
                .to_string();
                route_payload(&core, reply.into_bytes());
            })
        };
        let err = rpc_inner(&manager, &id, &invoke("runQuery", serde_json::json!(["COMMIT"])))
            .unwrap_err();
        replace_then_answer.join().expect("responder thread");
        assert!(err.starts_with("ERR_NATIVE_FILE_CHANGED:"), "{err}");
        assert!(core.pending.lock().unwrap().is_empty(), "the answer was consumed, not stranded");

        close_all_inner(&manager, "test over");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Admission: the size bound and the pin come from one stat, before any
    /// hold or spawn — a refused open leaves nothing behind.
    #[test]
    fn admission_refuses_oversize_files_and_pins_admitted_ones() {
        let dir = scratch("admit");
        let db = dir.join("picked.db");
        fs::write(&db, vec![0u8; 3 * 1024 * 1024]).unwrap(); // 3 MiB
        let err = admit_file(&db, Some(2 * 1024 * 1024)).unwrap_err();
        assert!(err.starts_with("ERR_FILE_TOO_LARGE:"), "{err}");
        assert!(err.contains("File size (3.00 MB) exceeds the maximum allowed size (2.00 MB)"), "{err}");
        assert!(err.contains("maxFileSize"), "{err}");
        // At the bound, unlimited (0), and absent all admit — and pin.
        let pinned = admit_file(&db, Some(3 * 1024 * 1024)).unwrap();
        assert_eq!(pinned, FileIdentity::of(&db).unwrap());
        assert_eq!(admit_file(&db, Some(0)).unwrap(), pinned);
        assert_eq!(admit_file(&db, None).unwrap(), pinned);
        // Not a regular file: refused as a path-authority failure.
        let err = admit_file(&dir, None).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        fs::remove_dir_all(&dir).unwrap();

        // Wired in: `open_inner` admits AFTER layer 1 and BEFORE the hold and
        // the spawn, and hands the pin to the sidecar it launches. No unit test
        // can invoke the command (it needs a live AppHandle), so pin the order
        // on the source like the other authority wiring is.
        let source = include_str!("native.rs");
        let body = source.split("pub(crate) fn open_inner(").nth(1).expect("open_inner");
        let body = &body[..body.find("fn core_for(").expect("core_for follows")];
        let layer1 = body.find("resolve_bound_path(").expect("layer 1");
        let admit = body.find("admit_file(&bound, max_bytes)").expect("admission");
        let hold = body.find("claim_native(").expect("the hold");
        let spawn = body.find("launch_sidecar(").expect("the spawn");
        assert!(layer1 < admit && admit < hold && hold < spawn, "order: allowlist, admit, hold, spawn");
        assert!(body.contains("Some(identity)"), "the launched sidecar must carry the pin");
    }

    #[test]
    fn locate_requires_all_native_artifacts() {
        let dir = scratch("locate");
        assert!(locate_native_dir(std::slice::from_ref(&dir)).is_none());
        fs::write(dir.join(SIDECAR_BINARY), b"#!").unwrap();
        assert!(
            locate_native_dir(std::slice::from_ref(&dir)).is_none(),
            "binary alone is not enough"
        );
        fs::write(dir.join(SIDECAR_SCRIPT), b"//").unwrap();
        assert!(locate_native_dir(std::slice::from_ref(&dir)).is_none(), "the bounded query-plan reader is required");
        fs::write(dir.join(QUERY_PLAN_LIBRARY), b"reader").unwrap();
        assert!(locate_native_dir(std::slice::from_ref(&dir)).is_some());
        // First candidate with the complete runtime wins.
        let empty = scratch("locate-empty");
        let found = locate_native_dir(&[empty.clone(), dir.clone()]).unwrap();
        assert_eq!(found.dir, dir);
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&empty).unwrap();
    }

    // -- shell export route --------------------------------------------------

    /// The forge-proofing seam, tested at both levels: `gate_envelope` (the
    /// classifier) and `rpc_inner` (the shared `native_rpc` authority path,
    /// live manager). A webview must not be able to reach the sidecar's
    /// shell-export handler by any spelling.
    #[test]
    fn gate_refuses_forged_shell_export_envelopes() {
        // The exact envelope shape the shell's own export path frames — from
        // the webview it must die at the channel check.
        let forged_shell = serde_json::json!({
            "channel": "shell",
            "content": { "kind": "export", "messageId": "rpc_1_1",
                          "method": "exportDatabase", "tempPath": "/tmp/evil/export" }
        })
        .to_string();
        let err = gate_envelope(&forged_shell, BOUND).unwrap_err();
        assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "{err}");

        // Keeping channel rpc and smuggling the export kind + a tempPath.
        let forged_kind = serde_json::json!({
            "channel": "rpc",
            "content": { "kind": "export", "messageId": "rpc_1_1",
                          "method": "exportTable", "tempPath": "/tmp/evil/export", "args": [] }
        })
        .to_string();
        let err = gate_envelope(&forged_kind, BOUND).unwrap_err();
        assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "{err}");

        // The sidecar shim method behind the export route must never become
        // an audited worker method; an invoke naming it is refused unlisted.
        assert!(!KNOWN_METHODS.contains(&"exportToPath"));
        let err = gate_envelope(
            &invoke("exportToPath", serde_json::json!(["/etc/passwd"])),
            BOUND,
        )
        .unwrap_err();
        assert!(err.contains("ERR_NATIVE_METHOD_UNLISTED"), "{err}");

        // The shell's messageId namespace cannot be squatted: a webview id
        // with the reserved prefix is refused outright (a squatted id would
        // otherwise pre-claim a pending slot and DoS the next shell export
        // at its `submit` duplicate check).
        for id in ["__shell_export_0", "__shell_export_999", "__shell_init_ping", "__shell"] {
            let envelope = serde_json::json!({
                "channel": "rpc",
                "content": { "kind": "invoke", "messageId": id, "targetMethod": "ping", "payload": [] }
            })
            .to_string();
            let err = gate_envelope(&envelope, BOUND).unwrap_err();
            assert!(err.contains("reserved"), "{id}: {err}");
        }

        // Through the real webview entry path: a manager with a live core
        // still refuses the forgery at the gate. The core has no writer
        // (writer_tx None), so if the gate did NOT refuse, submit would fail
        // with a DIFFERENT error ("write channel is closed") — asserting the
        // MALFORMED code proves the refusal happened at the gate, before
        // anything could be framed toward a sidecar.
        let (core, _receivers) = core_with_pending(&[]);
        let child = placeholder_child();
        let manager = NativeSidecar::default();
        let db_id = register_sidecar(
            &manager,
            SidecarHandle::unclaimed(Arc::clone(&core), Arc::new(Mutex::new(child))),
        )
        .expect("register");
        let err = rpc_inner(&manager, &db_id, &forged_shell).unwrap_err();
        assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "{err}");
        let err = rpc_inner(&manager, &db_id, &forged_kind).unwrap_err();
        assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "{err}");
        assert!(core.pending.lock().unwrap().is_empty(), "nothing may be registered");
        close_all_inner(&manager, "test over");
    }

    // -- Adversarial probes of the envelope gate + registry -----------------

    /// The gate parses the envelope with serde_json; the sidecar parses the
    /// SAME bytes with `JSON.parse`. A duplicate-key differential would let
    /// one see `"rpc"` where the other sees `"shell"` — i.e. a gate bypass
    /// with no code change on either side. Both take the LAST occurrence, and
    /// that agreement is pinned here rather than assumed: enabling
    /// serde_json's `preserve_order` (or any future first-wins policy) would
    /// silently open exactly that hole.
    #[test]
    fn duplicate_keys_resolve_last_wins_the_way_json_parse_does() {
        // channel: the LAST value is the one both sides act on.
        let shell_last = r#"{"channel":"rpc","channel":"shell","content":{"kind":"invoke","messageId":"rpc_1","targetMethod":"ping","payload":[]}}"#;
        let err = gate_envelope(shell_last, BOUND).unwrap_err();
        assert!(err.contains("envelope.channel must be"), "{err}");
        let rpc_last = r#"{"channel":"shell","channel":"rpc","content":{"kind":"invoke","messageId":"rpc_1","targetMethod":"ping","payload":[]}}"#;
        assert!(gate_envelope(rpc_last, BOUND).is_ok(), "the last channel wins");

        // targetMethod: a second, unlisted method is what gets gated.
        let method = r#"{"channel":"rpc","content":{"kind":"invoke","messageId":"rpc_1","targetMethod":"ping","targetMethod":"openArbitraryFile","payload":[]}}"#;
        let err = gate_envelope(method, BOUND).unwrap_err();
        assert!(err.contains("ERR_NATIVE_METHOD_UNLISTED"), "{err}");

        // messageId: a second id in the reserved namespace is still caught.
        let id = r#"{"channel":"rpc","content":{"kind":"invoke","messageId":"rpc_1","messageId":"__shell_export_0","targetMethod":"ping","payload":[]}}"#;
        let err = gate_envelope(id, BOUND).unwrap_err();
        assert!(err.contains("reserved"), "{err}");

        // kind, and the path check's own object: a second config.path is the
        // one compared against the binding.
        let kind = r#"{"channel":"rpc","content":{"kind":"invoke","kind":"export","messageId":"rpc_1","targetMethod":"ping","payload":[]}}"#;
        assert!(gate_envelope(kind, BOUND).is_err());
        let path = format!(
            r#"{{"channel":"rpc","content":{{"kind":"invoke","messageId":1,"targetMethod":"initializeDatabase","payload":["x",{{"path":"{BOUND}","path":"/etc/passwd"}}]}}}}"#
        );
        let err = gate_envelope(&path, BOUND).unwrap_err();
        assert!(err.contains("ERR_NATIVE_PATH_MISMATCH"), "{err}");
    }

    /// Every byte of an envelope is attacker-controlled in the threat model,
    /// so pathological NESTING has to be refused by the parser rather than
    /// overflowing the shell's stack — a stack overflow inside the gate is an
    /// abort, i.e. the whole app (every window, every unsaved database) killed
    /// from inside one webview. serde_json's recursion limit is what makes
    /// this fail closed; the same limit protects `native_export_table`'s
    /// `args_json` parse.
    #[test]
    fn a_pathologically_nested_envelope_is_refused_not_a_stack_overflow() {
        let deep = format!(
            r#"{{"channel":"rpc","content":{{"kind":"invoke","messageId":1,"targetMethod":"runQuery","payload":{}{}}}}}"#,
            "[".repeat(200_000),
            "]".repeat(200_000)
        );
        assert!(deep.len() < MAX_FRAME_BYTES as usize, "must not trip the size cap instead");
        let err = gate_envelope(&deep, BOUND).unwrap_err();
        assert!(err.contains("ERR_NATIVE_ENVELOPE_MALFORMED"), "{err}");

        // native_export_table's own parse of webview-authored args.
        let args = format!("{}{}", "[".repeat(200_000), "]".repeat(200_000));
        assert!(serde_json::from_str::<serde_json::Value>(&args).is_err());
    }

    /// A DbId is webview text of unbounded length and it is echoed into the
    /// refusal (and the shell's log). The echo must be excerpted, must be
    /// char-safe at the cut, and must never disturb a live sidecar.
    #[test]
    fn an_absurd_db_id_is_refused_with_a_bounded_char_safe_error() {
        let manager = NativeSidecar::default();
        let (_id, core, rx) = fake_entry(&manager, BOUND_A);

        for hostile in [
            "A".repeat(4 * 1024 * 1024),
            "é".repeat(4096),
            "\u{0}db_0".to_string(),
            "db_0 ".to_string(),
            "../db_0".to_string(),
            BOUND_A.to_string(),
        ] {
            let err = rpc_inner(&manager, &hostile, &invoke("runQuery", serde_json::json!(["SELECT 1"])))
                .unwrap_err();
            assert!(err.contains("ERR_NATIVE_UNKNOWN_DB"), "{err}");
            assert!(
                err.len() < 700,
                "the refusal echoed {} bytes of a hostile id",
                err.len()
            );
        }

        // The one real sidecar was never framed a byte of any of it.
        assert!(rx.try_recv().is_err());
        assert!(core.has_no_pending());
        assert!(!core.is_dead());
        close_all_inner(&manager, "test over");
    }

    /// The per-window open cap is the ONLY bound on webview-driven process
    /// creation. `open_serial` serialises the real `native_open`, but the cap
    /// must not depend on it: `register_sidecar` re-checks under the registry
    /// lock, so even a fully concurrent stampede admits exactly
    /// `MAX_NATIVE_SIDECARS` — and every refused handle is SHUT DOWN rather
    /// than dropped, so no unkillable child is left behind.
    #[test]
    fn the_open_cap_holds_under_a_concurrent_registration_stampede() {
        let manager = Arc::new(NativeSidecar::default());
        let racers: Vec<std::thread::JoinHandle<bool>> = (0..(MAX_NATIVE_SIDECARS * 3))
            .map(|_| {
                let manager = Arc::clone(&manager);
                std::thread::spawn(move || try_fake_entry(&manager, BOUND_A).is_ok())
            })
            .collect();
        let admitted = racers
            .into_iter()
            .map(|r| r.join().expect("racer thread"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(admitted, MAX_NATIVE_SIDECARS, "the cap was raced past");
        assert_eq!(open_ids(&manager).len(), MAX_NATIVE_SIDECARS);
        close_all_inner(&manager, "test over");
        assert!(open_ids(&manager).is_empty());
    }

    /// A MEASUREMENT, not an assertion
    /// about the shell's own code — hence `#[ignore]`.
    ///
    /// `#[tauri::command(async)]` on a SYNC body compiles to
    /// `resolver.respond_async_serialized(async move { <body> })`
    /// (tauri-macros 2.6.3 `body_async`), which is `async_runtime::spawn` onto
    /// tauri's global tokio MULTI-THREAD runtime — a worker thread, never
    /// `spawn_blocking`. So every blocking `(async)` command in this shell
    /// (`native_rpc`'s unbounded `recv`, `native_open`'s ≤10 s handshake, both
    /// export waits, both blocking dialogs) occupies one tokio WORKER for its
    /// whole duration, and the pool is only `available_parallelism()` deep —
    /// smaller, on this machine, than `MAX_NATIVE_SIDECARS`. This test blocks
    /// exactly that many tasks and shows the next one never runs.
    ///
    /// Run: `cargo test --lib -- --ignored blocking_command_bodies`.
    #[test]
    #[ignore = "MEASUREMENT of tauri's shared tokio pool, not a shell assertion; run with --ignored"]
    fn blocking_command_bodies_starve_tauris_shared_async_runtime() {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let mut releases = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (release_tx, release_rx) = mpsc::channel::<()>();
            releases.push(release_tx);
            let started = started_tx.clone();
            tauri::async_runtime::spawn(async move {
                // The pre-fix native_rpc shape: a blocking recv inside a sync
                // body that the macro wrapped in an async block.
                let _ = started.send(());
                let _ = release_rx.recv();
            });
        }
        for i in 0..workers {
            started_rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|e| panic!("blocking task {i} of {workers} never started: {e}"));
        }

        let (done_tx, done_rx) = mpsc::channel::<()>();
        tauri::async_runtime::spawn(async move {
            let _ = done_tx.send(());
        });
        let starved = done_rx.recv_timeout(Duration::from_secs(2)).is_err();

        for release in releases {
            let _ = release.send(());
        }
        assert!(
            starved,
            "expected the {workers}-worker pool to be saturated; it was not"
        );
        // …and the runtime recovers the moment the blocked bodies return.
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the queued task must run once a worker frees up");
    }

    // -- Fixes from the adversarial probes -----------------------------------

    /// BUG-1(a), the regression the ignored measurement above motivates.
    ///
    /// More concurrently-running slow queries than the shared runtime has
    /// workers, all parked waiting for a sidecar that will never answer — and
    /// the runtime keeps dispatching. Before the fix `native_rpc` blocked on
    /// `recv()` inside a body tauri had spawned onto a runtime WORKER, so
    /// `available_parallelism()` of these (12 here, fewer than the 16 sidecars
    /// one window may open) stopped every command in every window: File▸Open,
    /// Save As, native_open, native_close, both exports. Nothing timed out.
    ///
    /// Registries are per WINDOW, so one per query — that is also the shape
    /// of the real attack, several windows each running queries.
    #[test]
    fn concurrent_slow_queries_leave_the_runtime_dispatching() {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let slow = workers + 4;

        let mut managers = Vec::with_capacity(slow);
        let mut queues = Vec::with_capacity(slow);
        let mut cores = Vec::with_capacity(slow);
        for _ in 0..slow {
            let manager = Arc::new(NativeSidecar::default());
            let (id, core, rx) = fake_entry(&manager, BOUND_A);
            queues.push(rx);
            cores.push(Arc::clone(&core));
            managers.push((manager, id));
        }

        // Every one of these awaits an answer nobody will ever send.
        for (manager, id) in &managers {
            // Owned: the spawned future is 'static and outlives this loop.
            let manager = Arc::clone(manager);
            let id = id.clone();
            tauri::async_runtime::spawn(async move {
                let envelope = invoke("runQuery", serde_json::json!(["SELECT 1"]));
                let _ = rpc_awaited(&manager, &id, &envelope).await;
            });
        }
        // The frame reaching each sidecar's writer queue is the proof that
        // that query really is in flight (submit happens immediately before
        // the await).
        for (i, rx) in queues.iter().enumerate() {
            rx.recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|e| panic!("slow query {i} of {slow} never submitted: {e}"));
        }

        // The whole point: with `slow` queries outstanding, an unrelated task
        // still runs. Under the old blocking wait this never fires.
        let (probe_tx, probe_rx) = mpsc::channel::<()>();
        tauri::async_runtime::spawn(async move {
            let _ = probe_tx.send(());
        });
        probe_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|e| {
                panic!("{slow} slow queries starved the shared runtime ({workers} workers): {e}")
            });

        // Release every waiter through the normal crash-fanout path.
        for core in &cores {
            core.fail_all("ERR_NATIVE_SIDECAR_EXITED: test over");
        }
        for (manager, _) in &managers {
            close_all_inner(manager, "test over");
        }
    }

    /// BUG-1(a), the wait itself: an answer routes through the awaited
    /// responder exactly as it does through the blocking one, and a sidecar
    /// death still resolves the await rather than stranding it.
    #[test]
    fn an_awaited_rpc_resolves_on_an_answer_and_on_a_crash() {
        let manager = NativeSidecar::default();
        let (id, core, rx) = fake_entry(&manager, BOUND_A);
        let envelope = invoke("runQuery", serde_json::json!(["SELECT 1"]));

        let responder = answer_once(Arc::clone(&core), rx);
        let out = tauri::async_runtime::block_on(rpc_awaited(&manager, &id, &envelope))
            .expect("the answer must reach the awaiting command");
        assert!(out.contains(BOUND_A), "answered by the wrong sidecar: {out}");
        responder.join().unwrap();

        // Crash fanout resolves an awaited request the same way it resolves a
        // blocking one.
        let (id2, core2, _rx2) = fake_entry(&manager, BOUND_B);
        let dying = Arc::clone(&core2);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            dying.fail_all("ERR_NATIVE_SIDECAR_EXITED: the sidecar died");
        });
        let err = tauri::async_runtime::block_on(rpc_awaited(
            &manager,
            &id2,
            &invoke("runQuery", serde_json::json!(["SELECT 2"])),
        ))
        .unwrap_err();
        assert!(err.contains("ERR_NATIVE_SIDECAR_EXITED"), "{err}");

        close_all_inner(&manager, "test over");
    }

    /// BUG-1(b), the gate half. The sidecar arms its query deadline from
    /// `initializeDatabase` `config.queryTimeout`, which arrives from the
    /// PAGE — so "the sidecar's own deadline bounds runaway SQL" was a bound
    /// the attacker supplied. The gate now validates it, and absent still
    /// means "use the sidecar's own 30 s default".
    #[test]
    fn a_page_cannot_disarm_the_sidecars_query_deadline() {
        let init = |timeout: &str| {
            format!(
                r#"{{"channel":"rpc","content":{{"kind":"invoke","messageId":1,"targetMethod":"initializeDatabase","payload":["app.sqlite",{{"path":"{BOUND}"{timeout}}}]}}}}"#
            )
        };
        // Absent: fine.
        assert!(gate_envelope(&init(""), BOUND).is_ok());
        // Sane values: fine, including exactly the ceiling.
        for ok in [",\"queryTimeout\":30000", ",\"queryTimeout\":300000", ",\"queryTimeout\":1"] {
            assert!(gate_envelope(&init(ok), BOUND).is_ok(), "{ok}");
        }
        // Everything a page would use to disarm it.
        for hostile in [
            ",\"queryTimeout\":1e12",
            ",\"queryTimeout\":300001",
            ",\"queryTimeout\":0",
            ",\"queryTimeout\":-1",
            ",\"queryTimeout\":\"999999999\"",
            ",\"queryTimeout\":null",
            ",\"queryTimeout\":true",
        ] {
            let err = gate_envelope(&init(hostile), BOUND).unwrap_err();
            assert!(err.contains("ERR_NATIVE_QUERY_TIMEOUT_INVALID"), "{hostile}: {err}");
        }
        // Duplicate keys: the LAST one is what the sidecar reads, so it is
        // what the gate must judge (same differential as the channel/path
        // arms above).
        let err = gate_envelope(
            &init(",\"queryTimeout\":30000,\"queryTimeout\":1e12"),
            BOUND,
        )
        .unwrap_err();
        assert!(err.contains("ERR_NATIVE_QUERY_TIMEOUT_INVALID"), "{err}");
        assert!(gate_envelope(&init(",\"queryTimeout\":1e12,\"queryTimeout\":30000"), BOUND).is_ok());

        // The field is only meaningful on the one path-bearing method; other
        // methods are unaffected.
        assert!(gate_envelope(&invoke("runQuery", serde_json::json!(["SELECT 1"])), BOUND).is_ok());
    }

    /// D4, the native half. Two windows editing one file is silent data loss,
    /// and only the shell can see it: the per-window registries are isolated
    /// by design and the page-side host dedupes within its own window only.
    #[test]
    fn one_file_cannot_be_opened_read_write_by_two_windows() {
        let files = OpenFiles::default();
        let file = Path::new(BOUND_A);

        let first = claim_native(&files, file, "main").expect("first writer");
        let err = claim_native(&files, file, "db-0").unwrap_err();
        assert!(err.contains("ERR_NATIVE_DB_ALREADY_OPEN"), "{err}");
        assert!(err.contains("alpha.sqlite"), "{err}");
        assert!(err.contains("another SQLite Explorer window"), "{err}");
        // Even the SAME window is refused a second writable engine on one
        // file — the host dedupes in-page, so reaching here means it did not.
        let err = claim_native(&files, file, "main").unwrap_err();
        assert!(err.contains("already open in this window"), "{err}");

        // A DIFFERENT file in the other window is untouched by the hold.
        let _other = claim_native(&files, Path::new(BOUND_B), "db-0").expect("another file");

        drop(first);
        let _reclaimed = claim_native(&files, file, "db-0").expect("released on drop");
    }

    /// The hold is released by whichever registry path removes the handle —
    /// a close, a window teardown, a page-load reap, app exit — because it
    /// rides ON the handle rather than being unwound by each of those paths.
    #[test]
    fn every_path_that_drops_a_sidecar_releases_its_native_hold() {
        let files = OpenFiles::default();
        let file = Path::new(BOUND_A);

        // native_close.
        let manager = NativeSidecar::default();
        let hold = claim_native(&files, file, "main").expect("hold");
        let (id, _core, _rx) = try_fake_entry_claimed(&manager, BOUND_A, Some(hold)).unwrap();
        assert!(claim_native(&files, file, "db-0").is_err(), "held while open");
        close_inner(&manager, &id, "closed by native_close").expect("close");
        let released = claim_native(&files, file, "db-0").expect("released by close");
        drop(released);

        // The terminal drain (window destroyed / app exit).
        let hold = claim_native(&files, file, "main").expect("hold");
        let (_id, _core, _rx) = try_fake_entry_claimed(&manager, BOUND_A, Some(hold)).unwrap();
        assert!(claim_native(&files, file, "db-0").is_err(), "held while open");
        close_all_inner(&manager, "the window was closed");
        assert!(
            claim_native(&files, file, "db-0").is_ok(),
            "released by the terminal drain"
        );

        // A registration refused at the cap must not strand the hold either.
        let full = NativeSidecar::default();
        for _ in 0..MAX_NATIVE_SIDECARS {
            fake_entry(&full, BOUND_B);
        }
        let hold = claim_native(&files, Path::new("/Users/u/db/gamma.sqlite"), "main").unwrap();
        let refused = try_fake_entry_claimed(&full, BOUND_A, Some(hold))
            .err()
            .expect("the cap must refuse this registration");
        assert!(refused.contains("ERR_NATIVE_TOO_MANY_DATABASES"), "{refused}");
        assert!(
            claim_native(&files, Path::new("/Users/u/db/gamma.sqlite"), "db-0").is_ok(),
            "a refused registration must release the hold it was carrying"
        );
        close_all_inner(&full, "test over");
    }

    /// A hold dropped LATE must not take the file away from whoever holds it
    /// now. The window-destroyed teardown clears that window's entries
    /// eagerly, and its sidecar reaper runs DETACHED — so the `NativeHold`
    /// guards can drop an arbitrary number of milliseconds later, by which
    /// time another window may legitimately have opened the same file.
    #[test]
    fn a_late_native_hold_drop_cannot_release_the_next_owners_hold() {
        let files = OpenFiles::default();
        let file = Path::new(BOUND_A);

        let stale = claim_native(&files, file, "main").expect("first window");
        // The window goes away; the reaper still owns `stale`.
        forget_window_holds(&files, "main");
        let fresh = claim_native(&files, file, "db-0").expect("free once the window is gone");

        drop(stale); // …the detached reaper finally finishes.
        // The new owner's hold must still be standing.
        let err = claim_native(&files, file, "db-1").unwrap_err();
        assert!(err.contains("ERR_NATIVE_DB_ALREADY_OPEN"), "{err}");
        drop(fresh);
        let _third = claim_native(&files, file, "db-1").expect("free once db-0 lets go");
    }

    /// The WASM lane, which is the whole point of the push: a build with no
    /// native artifacts never calls `claim_native` at all, so if the page's
    /// reported set did not hold anything, two windows could each open one
    /// file and the second whole-image save would silently discard the
    /// first's edits.
    #[test]
    fn a_reported_open_file_blocks_every_other_windows_open_of_it() {
        let dir = scratch("reported-holds");
        let db = dir.join("shared.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let canonical = fs::canonicalize(&db).unwrap();
        let files = OpenFiles::default();

        // Window "main" opens it in WASM: a provisional hold at read time…
        hold_for_read(&files, &db, "main").expect("free");
        // …confirmed by the push that follows.
        assert_eq!(sync_reported(&files, "main", std::slice::from_ref(&db)).unwrap().installed, 1);
        assert_eq!(holder_of(&files, &db).as_deref(), Some("main"));

        // The second window is refused on BOTH engines.
        let err = hold_for_read(&files, &db, "db-0").unwrap_err();
        assert!(err.contains("ERR_NATIVE_DB_ALREADY_OPEN"), "{err}");
        assert!(err.contains("shared.db"), "{err}");
        assert!(err.contains("another SQLite Explorer window"), "{err}");
        assert!(!err.contains("db-0"), "the label must not leak: {err}");
        let err = claim_native(&files, &canonical, "db-0").unwrap_err();
        assert!(err.contains("ERR_NATIVE_DB_ALREADY_OPEN"), "{err}");

        // The owning window may still re-read it — that is a refresh — and
        // doing so must not downgrade its confirmed hold to an expiring one.
        hold_for_read(&files, &db, "main").expect("a refresh is not a second opener");
        assert_eq!(
            sync_reported_at(&files, "main", std::slice::from_ref(&db), Instant::now()).unwrap().installed,
            1
        );

        // THE case the naive design broke: close it here, open it there.
        assert_eq!(sync_reported(&files, "main", &[]).unwrap().installed, 0);
        assert_eq!(holder_of(&files, &db), None, "a close releases the file");
        hold_for_read(&files, &db, "db-0").expect("reopenable in the other window");
        assert_eq!(holder_of(&files, &db).as_deref(), Some("db-0"));

        // And a spelling that resolves to the same file collides with it —
        // the map is keyed canonically, not by the string the page sent.
        let spelled = dir.join(".").join("shared.db");
        let err = hold_for_read(&files, &spelled, "main").unwrap_err();
        assert!(err.contains("ERR_NATIVE_DB_ALREADY_OPEN"), "{err}");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// A window holding a WAL database natively keeps a log beside it through
    /// its own sidecar. Another window's WebAssembly read must name the open
    /// window, not send the user to close a program that is SQLite Explorer
    /// itself.
    #[test]
    fn a_file_open_in_another_window_is_named_as_that_even_with_a_log_beside_it() {
        let dir = scratch("open-elsewhere-with-log");
        let db = dir.join("shared.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        fs::write(dir.join("shared.db-wal"), [0u8; 4096]).unwrap();
        let canonical = fs::canonicalize(&db).unwrap();
        let files = OpenFiles::default();

        let native = claim_native(&files, &canonical, "main").unwrap();
        let err = admit_wasm_read(&files, &db, "db-0").unwrap_err();
        assert_eq!(err, already_open_error(&canonical, "main", "db-0"));
        // The owning window's own read is told about the log.
        let err = admit_wasm_read(&files, &db, "main").unwrap_err();
        assert!(err.starts_with("ERR_DATABASE_HAS_WAL"), "{err}");
        drop(native);

        // Nothing open anywhere: the log is the reason, and the refused read
        // claims nothing another window would then wait out.
        let err = admit_wasm_read(&files, &db, "db-0").unwrap_err();
        assert!(err.starts_with("ERR_DATABASE_HAS_WAL"), "{err}");
        assert_eq!(holder_of(&files, &db), None);
        fs::remove_file(dir.join("shared.db-wal")).unwrap();
        admit_wasm_read(&files, &db, "db-0").expect("no log, nothing open");
        assert_eq!(holder_of(&files, &db).as_deref(), Some("db-0"), "an admitted read holds the file");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_webassembly_read_gate_names_an_open_file_before_its_log_and_holds_last() {
        let source = include_str!("native.rs");
        let gate = source.split("pub(crate) fn admit_wasm_read").nth(1).expect("admit_wasm_read");
        let gate = &gate[..gate.find("\n}\n").expect("end")];
        let peek = gate.find("refuse_if_open_elsewhere(").expect("looks for another window's hold");
        let log = gate.find("snapshot_refusal(").expect("checks for a log");
        let hold = gate.find("hold_for_read(").expect("holds the file");
        assert!(peek < log && log < hold, "order: open elsewhere, log, hold");
    }

    #[test]
    fn the_open_elsewhere_look_claims_nothing_and_ignores_an_expired_hold() {
        let dir = scratch("open-elsewhere-ttl");
        let db = dir.join("stranded.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let canonical = fs::canonicalize(&db).unwrap();
        let files = OpenFiles::default();
        let t0 = Instant::now();
        refuse_if_open_elsewhere_at(&files, &canonical, "db-0", t0).expect("nothing open");
        assert_eq!(holder_of(&files, &db), None, "the look claims nothing");
        hold_for_read_at(&files, &canonical, "main", t0).expect("free");
        refuse_if_open_elsewhere_at(&files, &canonical, "main", t0).expect("the owner's own refresh");
        let err = refuse_if_open_elsewhere_at(&files, &canonical, "db-0", t0).unwrap_err();
        assert_eq!(err, already_open_error(&canonical, "main", "db-0"));
        refuse_if_open_elsewhere_at(&files, &canonical, "db-0", t0 + PROVISIONAL_HOLD_TTL)
            .expect("an expired provisional hold refuses nothing");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A page that reads and then never pushes — because its open threw, or
    /// because it is wedged — must not strand the file for the session. The
    /// read-time hold is the only one that expires, and only that one.
    #[test]
    fn a_provisional_hold_expires_but_a_reported_one_does_not() {
        let dir = scratch("provisional-expiry");
        let db = dir.join("stranded.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let canonical = fs::canonicalize(&db).unwrap();
        let files = OpenFiles::default();
        let t0 = Instant::now();

        hold_for_read_at(&files, &canonical, "main", t0).expect("free");
        // Still held right up to the deadline…
        let err = hold_for_read_at(
            &files,
            &canonical,
            "db-0",
            t0 + PROVISIONAL_HOLD_TTL - Duration::from_millis(1),
        )
        .unwrap_err();
        assert!(err.contains("ERR_NATIVE_DB_ALREADY_OPEN"), "{err}");
        // …and free once it passes.
        hold_for_read_at(&files, &canonical, "db-0", t0 + PROVISIONAL_HOLD_TTL)
            .expect("an unconfirmed hold must not outlive its TTL");

        // A CONFIRMED hold has no deadline: the push is event-driven, not a
        // heartbeat, so a database open and idle for a day is still open.
        assert_eq!(sync_reported(&files, "db-0", std::slice::from_ref(&db)).unwrap().installed, 1);
        let err = hold_for_read_at(
            &files,
            &canonical,
            "main",
            t0 + Duration::from_secs(86_400),
        )
        .unwrap_err();
        assert!(err.contains("ERR_NATIVE_DB_ALREADY_OPEN"), "{err}");

        // A native hold has no deadline either.
        forget_window_holds(&files, "db-0");
        let _native = claim_native_at(&files, &canonical, "db-0", t0).expect("free");
        assert!(
            claim_native_at(&files, &canonical, "main", t0 + Duration::from_secs(86_400))
                .is_err(),
            "a live sidecar holds its file for as long as it lives"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    /// The push is the page's ONLY input here, so it has to be bounded and it
    /// has to be unable to reach across windows.
    #[test]
    fn a_push_can_only_narrow_or_widen_its_own_windows_set() {
        let dir = scratch("push-authority");
        let mine = dir.join("mine.db");
        let theirs = dir.join("theirs.db");
        for file in [&mine, &theirs] {
            fs::write(file, b"SQLite format 3\0").unwrap();
        }
        let files = OpenFiles::default();

        sync_reported(&files, "main", std::slice::from_ref(&mine)).unwrap();
        sync_reported(&files, "db-0", std::slice::from_ref(&theirs)).unwrap();

        // Claiming the other window's file does nothing at all: not a
        // takeover, and — crucially — not a release either.
        sync_reported(&files, "db-0", &[theirs.clone(), mine.clone()]).unwrap();
        assert_eq!(holder_of(&files, &mine).as_deref(), Some("main"));
        assert_eq!(holder_of(&files, &theirs).as_deref(), Some("db-0"));

        // Dropping the other window's file from its own list does not release
        // it either — `main` still lists it.
        sync_reported(&files, "db-0", std::slice::from_ref(&theirs)).unwrap();
        assert_eq!(holder_of(&files, &mine).as_deref(), Some("main"));

        // An oversized push is rejected WHOLE, leaving the previous set
        // standing: truncating would release holds silently, which is the
        // exact failure this registry exists to prevent.
        let flood: Vec<PathBuf> = (0..MAX_REPORTED_OPEN_PATHS + 1).map(|_| mine.clone()).collect();
        let err = sync_reported(&files, "main", &flood).unwrap_err();
        assert!(err.contains("over the"), "{err}");
        assert_eq!(
            holder_of(&files, &mine).as_deref(),
            Some("main"),
            "a rejected push must not release anything"
        );

        // A path that cannot be resolved is dropped rather than held: it
        // names no file, so it can collide with nothing.
        let gone = dir.join("deleted.db");
        assert_eq!(sync_reported(&files, "main", &[mine.clone(), gone]).unwrap().installed, 1);

        fs::remove_dir_all(&dir).unwrap();
    }

    /// Teardown. A window that dies without a final push must strand nothing,
    /// and a page reload must drop what the outgoing document reported while
    /// leaving its still-running sidecars' holds alone.
    #[test]
    fn a_window_going_away_releases_everything_it_held() {
        let dir = scratch("teardown-holds");
        let wasm = dir.join("wasm.db");
        let native = dir.join("native.db");
        for file in [&wasm, &native] {
            fs::write(file, b"SQLite format 3\0").unwrap();
        }
        let native_canonical = fs::canonicalize(&native).unwrap();
        let files = OpenFiles::default();

        sync_reported(&files, "main", &[wasm.clone(), native.clone()]).unwrap();
        let hold = claim_native(&files, &native_canonical, "main").expect("native open");

        // A reload drops the page's half only: the sidecar is a live process
        // at that instant and is reaped detachedly.
        clear_page_holds(&files, "main");
        assert_eq!(holder_of(&files, &wasm), None, "the reported half is gone");
        assert_eq!(
            holder_of(&files, &native).as_deref(),
            Some("main"),
            "a live sidecar's hold survives its page"
        );

        // The window closing drops everything, without waiting on the reaper.
        forget_window_holds(&files, "main");
        assert_eq!(holder_of(&files, &native), None);
        hold_for_read(&files, &native, "db-0").expect("reopenable in another window");
        drop(hold);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn export_temp_dir_is_fresh_0700_and_fails_closed_on_planted_paths() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let parent = scratch("export-tempdir");
        let d1 = create_export_temp_dir(&parent).unwrap();
        let d2 = create_export_temp_dir(&parent).unwrap();
        assert_ne!(d1, d2, "two exports must never share a temp dir");
        for dir in [&d1, &d2] {
            let meta = fs::metadata(dir).unwrap();
            assert!(meta.is_dir());
            assert_eq!(meta.permissions().mode() & 0o777, 0o700, "the dir IS the boundary");
            assert_eq!(dir.parent().unwrap(), parent.as_path(), "same fs as dest");
            assert!(dir
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(".sqlite-export-"));
        }

        // Planted occupants at the exact path fail closed: a file…
        let occupied_file = parent.join("occupied-file");
        fs::write(&occupied_file, b"x").unwrap();
        assert!(create_export_temp_dir_at(&occupied_file).is_err());
        // …a directory (an attacker-owned dir must never be adopted)…
        let occupied_dir = parent.join("occupied-dir");
        fs::create_dir(&occupied_dir).unwrap();
        assert!(create_export_temp_dir_at(&occupied_dir).is_err());
        // …a symlink to a directory (mkdir must not follow and create behind it)…
        let lure = parent.join("lure-target");
        fs::create_dir(&lure).unwrap();
        let link = parent.join("planted-link");
        symlink(&lure, &link).unwrap();
        assert!(create_export_temp_dir_at(&link).is_err());
        assert_eq!(
            fs::read_dir(&lure).unwrap().count(),
            0,
            "nothing may appear behind the planted symlink"
        );
        // …and a dangling symlink (mkdir EEXISTs on the entry itself).
        let dangling = parent.join("dangling-link");
        symlink(parent.join("nowhere"), &dangling).unwrap();
        assert!(create_export_temp_dir_at(&dangling).is_err());

        fs::remove_dir_all(&parent).unwrap();
    }

    /// `TempDirCleanup`'s Drop clears a NON-EMPTY temp dir — the base case the
    /// timeout-race retry must preserve (a partial export plus its VACUUM
    /// journal still standing when the guard runs). The ENOTEMPTY retry branch
    /// itself is deliberately NOT unit-tested: forcing the first remove_dir_all
    /// to fail not-empty and a retry to then succeed needs a writer racing the
    /// readdir↔rmdir window, which is inherently flaky; the branch is a brief
    /// sleep plus one identical retry and is self-evidently correct.
    #[test]
    fn temp_dir_cleanup_removes_a_populated_dir_on_drop() {
        let parent = scratch("cleanup-drop");
        let temp = create_export_temp_dir(&parent).unwrap();
        fs::write(temp.join("export"), b"partial export bytes").unwrap();
        fs::write(temp.join("export-journal"), b"vacuum journal").unwrap();
        assert!(temp.exists());
        {
            let _cleanup = TempDirCleanup(temp.clone());
        } // Drop runs here.
        assert!(!temp.exists(), "cleanup must remove the populated temp dir");
        assert_no_export_temp_dirs(&parent);
        fs::remove_dir_all(&parent).unwrap();
    }

    /// A writer-queue-backed core plus the queue's receiving end, for tests
    /// that play the sidecar themselves (no threads are wired).
    fn export_core() -> (Arc<SidecarCore>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE_CAP);
        (Arc::new(SidecarCore::new(BOUND.to_string(), None, tx)), rx)
    }

    fn assert_no_export_temp_dirs(dir: &Path) {
        let leftovers: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".sqlite-export-"))
            .collect();
        assert!(leftovers.is_empty(), "temp dirs left behind: {leftovers:?}");
    }

    /// Drives `export_to_dest` against an in-process fake sidecar: `act` gets
    /// the tempPath the shell constructed and returns the reply's content
    /// fields (`success` etc.); the reply is routed back by the echoed
    /// messageId exactly as `route_payload` does in production. Returns the
    /// outcome and the envelope the "sidecar" received.
    fn drive_fake_export(
        dest: &Path,
        method: &'static str,
        args: Option<serde_json::Value>,
        act: impl FnOnce(&Path) -> serde_json::Value + Send + 'static,
    ) -> (Result<String, String>, serde_json::Value) {
        let (core, writer_rx) = export_core();
        let fake = {
            let core = Arc::clone(&core);
            std::thread::spawn(move || {
                let raw = writer_rx.recv().expect("the export request must be enqueued");
                let env: serde_json::Value = serde_json::from_slice(&raw).expect("envelope parses");
                let temp = PathBuf::from(
                    env.pointer("/content/tempPath")
                        .and_then(|v| v.as_str())
                        .expect("envelope carries a tempPath"),
                );
                let mut content = act(&temp);
                content["kind"] = "export-result".into();
                content["messageId"] = env.pointer("/content/messageId").unwrap().clone();
                let reply =
                    serde_json::json!({ "channel": "shell", "content": content }).to_string();
                route_payload(&core, reply.into_bytes());
                env
            })
        };
        let outcome = export_to_dest(&core, method, args, dest, Duration::from_secs(5));
        let env = fake.join().expect("fake sidecar thread");
        assert!(
            core.pending.lock().unwrap().is_empty(),
            "no pending entry may remain after an export"
        );
        (outcome, env)
    }

    #[test]
    fn export_roundtrip_moves_the_file_and_removes_the_temp_dir() {
        let dir = scratch("export-ok");
        let dest = dir.join("out.db");
        let (outcome, env) = drive_fake_export(&dest, "exportDatabase", None, |temp| {
            // While the request is in flight the temp dir must already be the
            // shell's 0700 boundary.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(temp.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o700, "temp dir must be 0700 while the sidecar writes");
            }
            fs::write(temp, b"export bytes").unwrap();
            serde_json::json!({ "success": true, "bytesWritten": 12 })
        });
        assert_eq!(outcome.unwrap(), "out.db");
        assert_eq!(fs::read(&dest).unwrap(), b"export bytes");

        // The envelope the sidecar saw: shell channel, export kind, the
        // reserved id namespace, a tempPath named "export" inside a fresh
        // dot-dir in dest's parent — and NO args member for exportDatabase.
        assert_eq!(env.pointer("/channel").unwrap(), "shell");
        assert_eq!(env.pointer("/content/kind").unwrap(), "export");
        assert_eq!(env.pointer("/content/method").unwrap(), "exportDatabase");
        let id = env.pointer("/content/messageId").unwrap().as_str().unwrap();
        assert!(id.starts_with(SHELL_MESSAGE_ID_PREFIX), "{id}");
        assert!(env.pointer("/content/args").is_none());
        let temp = PathBuf::from(env.pointer("/content/tempPath").unwrap().as_str().unwrap());
        assert_eq!(temp.file_name().unwrap(), "export");
        let temp_dir = temp.parent().unwrap();
        assert_eq!(temp_dir.parent().unwrap(), dir.as_path());
        assert!(!temp_dir.exists(), "the temp dir must be removed after success");
        assert_no_export_temp_dirs(&dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn export_table_args_are_forwarded_verbatim() {
        let dir = scratch("export-args");
        let dest = dir.join("t.csv");
        let args = serde_json::json!([
            { "table": "t" }, null, null, null,
            { "format": "csv", "maxExportBytes": 536870912u64 }
        ]);
        let expected = args.clone();
        let (outcome, env) = drive_fake_export(&dest, "exportTable", Some(args), |temp| {
            fs::write(temp, b"a,b\n1,2\n").unwrap();
            serde_json::json!({ "success": true, "bytesWritten": 8 })
        });
        assert_eq!(outcome.unwrap(), "t.csv");
        assert_eq!(env.pointer("/content/method").unwrap(), "exportTable");
        assert_eq!(env.pointer("/content/args").unwrap(), &expected);
        assert_eq!(fs::read(&dest).unwrap(), b"a,b\n1,2\n");
        assert_no_export_temp_dirs(&dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn export_error_reply_cleans_the_temp_dir_and_leaves_no_dest() {
        let dir = scratch("export-err");
        let dest = dir.join("out.db");
        let (outcome, _env) = drive_fake_export(&dest, "exportDatabase", None, |_temp| {
            serde_json::json!({ "success": false,
                "error": { "name": "Error", "message": "disk full", "code": "ENOSPC" } })
        });
        let err = outcome.unwrap_err();
        assert!(err.contains("ERR_NATIVE_EXPORT_FAILED"), "{err}");
        assert!(err.contains("ENOSPC") && err.contains("disk full"), "{err}");
        assert!(!dest.exists(), "no partial dest file may exist");
        assert_no_export_temp_dirs(&dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A success reply whose file is missing, or whose size disagrees with
    /// the reported bytesWritten, must fail closed — never publish to dest.
    #[test]
    fn export_success_reply_must_match_the_file_on_disk() {
        let dir = scratch("export-liar");
        let dest = dir.join("out.db");
        // No file written at all.
        let (outcome, _env) = drive_fake_export(&dest, "exportDatabase", None, |_temp| {
            serde_json::json!({ "success": true, "bytesWritten": 12 })
        });
        let err = outcome.unwrap_err();
        assert!(err.contains("ERR_NATIVE_EXPORT_FAILED"), "{err}");
        assert!(!dest.exists());
        // File written but the reported size disagrees.
        let (outcome, _env) = drive_fake_export(&dest, "exportDatabase", None, |temp| {
            fs::write(temp, b"short").unwrap();
            serde_json::json!({ "success": true, "bytesWritten": 999 })
        });
        let err = outcome.unwrap_err();
        assert!(err.contains("ERR_NATIVE_EXPORT_FAILED"), "{err}");
        assert!(!dest.exists());
        assert_no_export_temp_dirs(&dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Defense in depth behind the 0700 dir: were a symlink ever to sit at
    /// the temp target when the move begins, the shell refuses to follow it
    /// (the sidecar's own 'wx' open is the first line; the live e2e proves
    /// that one against the real binary).
    #[cfg(unix)]
    #[test]
    fn export_refuses_a_symlink_at_the_temp_target() {
        use std::os::unix::fs::symlink;
        let dir = scratch("export-symlink");
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"victim contents").unwrap();
        let dest = dir.join("out.db");
        let victim_for_act = victim.clone();
        let (outcome, _env) = drive_fake_export(&dest, "exportDatabase", None, move |temp| {
            symlink(&victim_for_act, temp).unwrap();
            serde_json::json!({ "success": true, "bytesWritten": 15 })
        });
        let err = outcome.unwrap_err();
        assert!(err.contains("ERR_NATIVE_EXPORT_FAILED"), "{err}");
        assert_eq!(fs::read(&victim).unwrap(), b"victim contents");
        assert!(!dest.exists());
        assert_no_export_temp_dirs(&dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The sidecar's documented non-reply behaviour (unknown kind / stale
    /// bundle → DROP with a stderr log) must never strand the shell: the
    /// bounded timeout fires, the pending entry is unregistered, the temp dir
    /// is removed, and no dest file exists.
    #[test]
    fn export_timeout_surfaces_structurally_and_cleans_up() {
        let dir = scratch("export-timeout");
        let dest = dir.join("out.csv");
        let (core, writer_rx) = export_core(); // held, never served: the drop case
        let started = Instant::now();
        let err = export_to_dest(
            &core,
            "exportTable",
            Some(serde_json::json!([{ "table": "t" }])),
            &dest,
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(err.contains("ERR_NATIVE_EXPORT_TIMEOUT"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3), "the timeout must be bounded");
        assert!(
            core.pending.lock().unwrap().is_empty(),
            "the timed-out entry must be unregistered"
        );
        assert!(!dest.exists());
        assert_no_export_temp_dirs(&dir);
        drop(writer_rx);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A dead sidecar refuses the submit with its recorded reason; the temp
    /// dir must still be cleaned up.
    #[test]
    fn export_against_a_dead_sidecar_cleans_up() {
        let dir = scratch("export-dead");
        let dest = dir.join("out.db");
        let (core, _writer_rx) = export_core();
        core.fail_all("ERR_NATIVE_SIDECAR_EXITED: gone");
        let err =
            export_to_dest(&core, "exportDatabase", None, &dest, Duration::from_secs(1)).unwrap_err();
        assert!(err.contains("ERR_NATIVE_SIDECAR_EXITED"), "{err}");
        assert!(!dest.exists());
        assert_no_export_temp_dirs(&dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// An over-cap export envelope (hostile/huge args) is refused BEFORE
    /// submit — it must never reach the writer thread, where an over-cap
    /// frame would kill the writer and fan out the whole session.
    #[test]
    fn export_oversized_args_are_refused_before_the_writer() {
        let dir = scratch("export-oversize");
        let dest = dir.join("out.csv");
        let (core, writer_rx) = export_core();
        let huge = serde_json::json!(["x".repeat(MAX_FRAME_BYTES as usize)]);
        let err = export_to_dest(&core, "exportTable", Some(huge), &dest, Duration::from_secs(1))
            .unwrap_err();
        assert!(err.contains("ERR_NATIVE_FRAME_TOO_LARGE"), "{err}");
        assert!(
            writer_rx.try_recv().is_err(),
            "nothing may have been enqueued toward the sidecar"
        );
        assert!(core.pending.lock().unwrap().is_empty());
        assert!(!dest.exists());
        assert_no_export_temp_dirs(&dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    // -- live sidecar (requires built artifacts; run with --ignored) -------

    /// End-to-end against the REAL binary + committed bundle: spawn through
    /// the production launch path (env allowlist, cwd pin, handshake),
    /// initializeDatabase + fetchSchema through the production gate+submit
    /// flow, layer-3 refusal of a retarget, then clean EOF shutdown (exit 0).
    #[test]
    #[ignore = "needs viewer-dist/native artifacts (npm run build:viewer); run: cargo test --lib -- --ignored"]
    fn live_sidecar_end_to_end() {
        let native_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("viewer-dist")
            .join("native");
        let paths = locate_native_dir(&[native_dir])
            .expect("build the native artifacts first: npm run build:viewer");

        let dir = scratch("live");
        let db = dir.join("live 東京 space.db");
        fs::write(&db, b"").unwrap(); // a zero-byte file is a valid empty SQLite db
        let bound = fs::canonicalize(&db).unwrap();
        let bound_str = bound.to_str().unwrap().to_string();

        let identity = FileIdentity::of(Path::new(&bound_str)).expect("identity");
        let (core, child) = launch_sidecar(&paths, &bound_str, false, Some(identity)).expect("spawn + handshake");

        let rpc = |method: &str, id: &str, payload: serde_json::Value| -> serde_json::Value {
            let envelope = serde_json::json!({
                "channel": "rpc",
                "content": { "kind": "invoke", "messageId": id, "targetMethod": method, "payload": payload }
            })
            .to_string();
            let key = gate_envelope(&envelope, &core.bound_path).expect("gate");
            let rx = core.submit(key, &envelope).expect("submit");
            let text = rx
                .recv_timeout(Duration::from_secs(15))
                .expect("response within 15s")
                .expect("rpc ok");
            serde_json::from_str(&text).expect("response parses")
        };

        let init = rpc(
            "initializeDatabase",
            "t-init",
            serde_json::json!(["live.db", { "path": bound_str, "readOnlyMode": false }]),
        );
        assert_eq!(init["content"]["success"], serde_json::json!(true), "{init}");

        let schema = rpc("fetchSchema", "t-schema", serde_json::json!([]));
        assert_eq!(schema["content"]["success"], serde_json::json!(true), "{schema}");

        // Layer 3 refuses a retarget BEFORE anything reaches the sidecar.
        let evil = serde_json::json!({
            "channel": "rpc",
            "content": { "kind": "invoke", "messageId": "t-evil", "targetMethod": "initializeDatabase",
                          "payload": ["x", { "path": "/etc/passwd" }] }
        })
        .to_string();
        let err = gate_envelope(&evil, &core.bound_path).unwrap_err();
        assert!(err.contains("ERR_NATIVE_PATH_MISMATCH"), "{err}");

        // Graceful shutdown: dropping the queue sender lets the writer drain
        // and close stdin (EOF); the sidecar exits 0.
        *core.writer_tx.lock().unwrap() = None;
        let status = wait_or_kill(&child, Duration::from_secs(5), false);
        assert!(status.contains("exit code 0"), "expected clean EOF exit, got: {status}");
        core.fail_all("test over");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// TWO real sidecars at once, driven through the production registry
    /// (`register_sidecar` → `rpc_awaited` → `close_inner`/`close_all_inner`):
    /// each answers ONLY its own database, an envelope routed by DbId never
    /// reaches the other process, and closing one leaves the other serving.
    /// The two databases are given disjoint schemas so every answer names the
    /// connection it came from.
    #[test]
    #[ignore = "needs viewer-dist/native artifacts (npm run build:viewer); run: cargo test --lib -- --ignored"]
    fn live_two_sidecars_serve_their_own_databases() {
        let native_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("viewer-dist")
            .join("native");
        let paths = locate_native_dir(&[native_dir])
            .expect("build the native artifacts first: npm run build:viewer");

        let dir = scratch("live-two");
        // Zero-byte files are valid empty SQLite databases; each sidecar
        // creates its OWN table, so a schema answer names its database.
        let db_a = dir.join("alpha.db");
        let db_b = dir.join("beta.db");
        fs::write(&db_a, b"").unwrap();
        fs::write(&db_b, b"").unwrap();
        let bound_a = fs::canonicalize(&db_a).unwrap().to_str().unwrap().to_string();
        let bound_b = fs::canonicalize(&db_b).unwrap().to_str().unwrap().to_string();

        let manager = NativeSidecar::default();
        let identity_a = FileIdentity::of(Path::new(&bound_a)).expect("identity A");
        let identity_b = FileIdentity::of(Path::new(&bound_b)).expect("identity B");
        let (core_a, child_a) = launch_sidecar(&paths, &bound_a, false, Some(identity_a)).expect("spawn A");
        let (core_b, child_b) = launch_sidecar(&paths, &bound_b, false, Some(identity_b)).expect("spawn B");
        let id_a = register_sidecar(
            &manager,
            SidecarHandle::unclaimed(Arc::clone(&core_a), Arc::clone(&child_a)),
        )
        .expect("register A");
        let id_b = register_sidecar(
            &manager,
            SidecarHandle::unclaimed(Arc::clone(&core_b), Arc::clone(&child_b)),
        )
        .expect("register B");
        assert_ne!(id_a, id_b);
        eprintln!("[e2e] two live sidecars registered: {id_a} → alpha.db, {id_b} → beta.db");

        // Everything below goes through the REAL command path, awaited
        // exactly as `native_rpc` awaits it: `rpc_awaited` resolves the
        // sidecar by DbId, gates the envelope against that sidecar's own
        // bound path, and waits on the oneshot rather than on a thread.
        let rpc = |db_id: &str, method: &str, id: &str, payload: serde_json::Value| -> String {
            let envelope = serde_json::json!({
                "channel": "rpc",
                "content": { "kind": "invoke", "messageId": id, "targetMethod": method, "payload": payload }
            })
            .to_string();
            tauri::async_runtime::block_on(rpc_awaited(&manager, db_id, &envelope))
                .unwrap_or_else(|e| panic!("{method} on {db_id} failed: {e}"))
        };
        let ok = |text: &str| {
            let value: serde_json::Value = serde_json::from_str(text).expect("response parses");
            assert_eq!(value["content"]["success"], serde_json::json!(true), "{text}");
        };

        ok(&rpc(&id_a, "initializeDatabase", "a-init",
            serde_json::json!(["alpha.db", { "path": bound_a, "readOnlyMode": false }])));
        ok(&rpc(&id_b, "initializeDatabase", "b-init",
            serde_json::json!(["beta.db", { "path": bound_b, "readOnlyMode": false }])));

        ok(&rpc(&id_a, "runQuery", "a-ddl",
            serde_json::json!(["CREATE TABLE alpha_only(id INTEGER PRIMARY KEY, a TEXT)"])));
        ok(&rpc(&id_b, "runQuery", "b-ddl",
            serde_json::json!(["CREATE TABLE beta_only(id INTEGER PRIMARY KEY, b TEXT)"])));

        // Each connection sees ONLY its own schema — the cross-talk proof at
        // the engine level.
        let schema_a = rpc(&id_a, "fetchSchema", "a-schema", serde_json::json!([]));
        assert!(schema_a.contains("alpha_only") && !schema_a.contains("beta_only"), "{schema_a}");
        let schema_b = rpc(&id_b, "fetchSchema", "b-schema", serde_json::json!([]));
        assert!(schema_b.contains("beta_only") && !schema_b.contains("alpha_only"), "{schema_b}");

        // …and at the filesystem level: each write landed in its own file.
        let bytes_a = fs::read(&db_a).unwrap();
        let bytes_b = fs::read(&db_b).unwrap();
        let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        assert!(contains(&bytes_a, b"alpha_only") && !contains(&bytes_a, b"beta_only"));
        assert!(contains(&bytes_b, b"beta_only") && !contains(&bytes_b, b"alpha_only"));
        eprintln!("[e2e] disjoint schemas confirmed in both processes AND on disk");

        // A DB-A envelope naming DB-B's file is a retarget attempt: refused by
        // layer 3 against A's bound path, and B is untouched.
        let retarget = serde_json::json!({
            "channel": "rpc",
            "content": { "kind": "invoke", "messageId": "a-evil", "targetMethod": "initializeDatabase",
                          "payload": ["beta", { "path": bound_b, "readOnlyMode": false }] }
        })
        .to_string();
        let err = tauri::async_runtime::block_on(rpc_awaited(&manager, &id_a, &retarget)).unwrap_err();
        assert!(err.contains("ERR_NATIVE_PATH_MISMATCH"), "{err}");

        // An unknown id reaches NOBODY (and the DB's path is not an id).
        for bogus in ["db_404", bound_a.as_str(), ""] {
            let err = tauri::async_runtime::block_on(rpc_awaited(&manager, bogus, &retarget)).unwrap_err();
            assert!(err.contains("ERR_NATIVE_UNKNOWN_DB"), "{bogus:?}: {err}");
        }
        // Both sidecars are still healthy and still their own after all that.
        let schema_a = rpc(&id_a, "fetchSchema", "a-schema-2", serde_json::json!([]));
        assert!(schema_a.contains("alpha_only") && !schema_a.contains("beta_only"), "{schema_a}");
        let schema_b = rpc(&id_b, "fetchSchema", "b-schema-2", serde_json::json!([]));
        assert!(schema_b.contains("beta_only") && !schema_b.contains("alpha_only"), "{schema_b}");
        eprintln!("[e2e] retarget + unknown-id refusals left both sessions intact");

        // Closing A leaves B serving; A's id then refuses like any unknown id.
        close_inner(&manager, &id_a, "ERR_NATIVE_SIDECAR_EXITED: closed by native_close")
            .expect("close A");
        let status_a = child_a.lock().unwrap().try_wait().expect("wait A");
        assert_eq!(status_a.and_then(|s| s.code()), Some(0), "A must exit 0 on stdin EOF");
        let err = tauri::async_runtime::block_on(rpc_awaited(&manager, &id_a, &retarget)).unwrap_err();
        assert!(err.contains("ERR_NATIVE_UNKNOWN_DB"), "{err}");
        let schema_b = rpc(&id_b, "fetchSchema", "b-schema-3", serde_json::json!([]));
        assert!(schema_b.contains("beta_only"), "B must still serve after A closed: {schema_b}");
        eprintln!("[e2e] closed {id_a} (exit 0); {id_b} still serving");

        // App exit closes what is left.
        close_all_inner(&manager, "ERR_NATIVE_SIDECAR_EXITED: the application is exiting");
        assert!(open_ids(&manager).is_empty());
        let status_b = child_b.lock().unwrap().try_wait().expect("wait B");
        assert_eq!(status_b.and_then(|s| s.code()), Some(0), "B must exit 0 on stdin EOF");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The full export route against the REAL sidecar (requires a bundle that
    /// carries the shell-export handler, as every build from viewer/ does —
    /// `npm run build:viewer`): a > 16 MiB database
    /// is exported BOTH ways end to end through the production
    /// `export_to_dest` flow, proving the bytes never rode a frame (the frame
    /// cap is 16 MiB), the dest files are valid, and the temp dirs are gone.
    /// Also proves the sidecar's 'wx' open fails closed on a planted symlink.
    #[test]
    #[ignore = "needs the post-export-route native artifacts + sqlite3 CLI; run: cargo test --lib -- --ignored"]
    fn live_export_route_end_to_end() {
        const FRAME_CAP: u64 = MAX_FRAME_BYTES as u64; // 16_777_216

        let native_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("viewer-dist")
            .join("native");
        let paths = locate_native_dir(&[native_dir])
            .expect("build the native artifacts first: npm run build:viewer");

        let dir = scratch("live-export");
        let db = dir.join("big.db");
        // ~20.5 MiB of incompressible hex text: 10_000 rows × 2_048 chars.
        let seed = Command::new("sqlite3")
            .arg(&db)
            .arg(
                "CREATE TABLE t(id INTEGER PRIMARY KEY, data TEXT); \
                 WITH RECURSIVE c(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM c WHERE x<10000) \
                 INSERT INTO t(data) SELECT hex(randomblob(1024)) FROM c;",
            )
            .output()
            .expect("sqlite3 CLI must be available");
        assert!(seed.status.success(), "fixture seed failed: {}", String::from_utf8_lossy(&seed.stderr));
        let db_size = fs::metadata(&db).unwrap().len();
        assert!(db_size > FRAME_CAP, "fixture too small to prove anything: {db_size} bytes");

        let bound = fs::canonicalize(&db).unwrap();
        let bound_str = bound.to_str().unwrap().to_string();
        let identity = FileIdentity::of(Path::new(&bound_str)).expect("identity");
        let (core, child) = launch_sidecar(&paths, &bound_str, false, Some(identity)).expect("spawn + handshake");

        // Initialize through the production gate+submit path.
        let init = serde_json::json!({
            "channel": "rpc",
            "content": { "kind": "invoke", "messageId": "t-init", "targetMethod": "initializeDatabase",
                          "payload": ["big.db", { "path": bound_str, "readOnlyMode": false }] }
        })
        .to_string();
        let key = gate_envelope(&init, &core.bound_path).expect("gate");
        let rx = core.submit(key, &init).expect("submit");
        let text = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("init response")
            .expect("init ok");
        let init_response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(init_response["content"]["success"], serde_json::json!(true), "{init_response}");

        // 1) exportDatabase: VACUUM INTO → temp → atomic move → dest.
        let dest_db = dir.join("exported.db");
        let saved = export_to_dest(&core, "exportDatabase", None, &dest_db, Duration::from_secs(120))
            .expect("database export succeeds");
        assert_eq!(saved, "exported.db");
        let exported_size = fs::metadata(&dest_db).unwrap().len();
        assert!(
            exported_size > FRAME_CAP,
            "exported DB is only {exported_size} bytes — did not exceed the frame cap"
        );
        let check = Command::new("sqlite3")
            .arg(&dest_db)
            .arg("PRAGMA integrity_check; SELECT count(*) FROM t;")
            .output()
            .expect("sqlite3 validates the export");
        let out = String::from_utf8_lossy(&check.stdout);
        assert!(check.status.success() && out.contains("ok") && out.contains("10000"),
            "exported DB failed validation: {out} {}", String::from_utf8_lossy(&check.stderr));
        eprintln!(
            "[e2e] exportDatabase: {exported_size} bytes (> {FRAME_CAP} cap), integrity_check ok, 10000 rows"
        );

        // 2) exportTable: in-process CSV → chunks to temp ('wx') → move.
        let dest_csv = dir.join("t.csv");
        let args = serde_json::json!([
            { "table": "t" }, null, null, null,
            { "format": "csv", "maxExportBytes": 536870912u64 }
        ]);
        let saved = export_to_dest(&core, "exportTable", Some(args), &dest_csv, Duration::from_secs(120))
            .expect("table export succeeds");
        assert_eq!(saved, "t.csv");
        let csv = fs::read(&dest_csv).unwrap();
        assert!(
            csv.len() as u64 > FRAME_CAP,
            "exported CSV is only {} bytes — did not exceed the frame cap",
            csv.len()
        );
        let lines = csv.iter().filter(|b| **b == b'\n').count();
        assert!(lines >= 10_000, "CSV row count wrong: {lines} newlines");
        let header = csv.split(|b| *b == b'\n').next().unwrap();
        assert!(
            String::from_utf8_lossy(header).contains("id"),
            "CSV header missing: {:?}",
            String::from_utf8_lossy(header)
        );
        eprintln!(
            "[e2e] exportTable: {} bytes (> {FRAME_CAP} cap), {lines} newlines, header {:?}",
            csv.len(),
            String::from_utf8_lossy(header)
        );

        // No temp dir survived either export.
        assert_no_export_temp_dirs(&dir);

        // 3) The sidecar's own 'wx' fail-close, against the real binary: a
        // symlink planted at the target path must refuse, not write through.
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let victim = dir.join("victim.txt");
            fs::write(&victim, b"victim contents").unwrap();
            let planted_dir = dir.join("planted");
            fs::create_dir(&planted_dir).unwrap();
            let planted = planted_dir.join("export");
            symlink(&victim, &planted).unwrap();
            let args = serde_json::json!([
                { "table": "t" }, null, null, null, { "format": "csv", "maxExportBytes": 536870912u64 }
            ]);
            let err = export_via_sidecar(
                &core,
                "exportTable",
                planted.to_str().unwrap(),
                Some(args),
                Duration::from_secs(60),
            )
            .expect_err("a planted symlink at the target must fail closed");
            assert!(err.contains("ERR_NATIVE_EXPORT_FAILED"), "{err}");
            assert_eq!(fs::read(&victim).unwrap(), b"victim contents", "victim written through!");
            assert!(fs::symlink_metadata(&planted).unwrap().file_type().is_symlink());
        }

        // Clean shutdown (exit 0), as the production close path does.
        *core.writer_tx.lock().unwrap() = None;
        let status = wait_or_kill(&child, Duration::from_secs(5), false);
        assert!(status.contains("exit code 0"), "expected clean EOF exit, got: {status}");
        core.fail_all("test over");
        fs::remove_dir_all(&dir).unwrap();
    }
}
