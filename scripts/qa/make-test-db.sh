#!/usr/bin/env bash
# make-test-db.sh <path> [--wal]
#   --wal  leave the DB in WAL journal mode (a -wal sidecar file is created), to
#          exercise the native engine's writable-WAL path vs the WASM engine's
#          WAL-is-read-only notice.
set -euo pipefail
DB="${1:?usage: make-test-db.sh <path> [--wal]}"
WAL_MODE="${2:-}"
rm -f "$DB" "$DB-wal" "$DB-shm"
sqlite3 "$DB" <<'EOF'
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT, age INTEGER, balance REAL, avatar BLOB, meta JSON, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE "order items" ("item id" INTEGER PRIMARY KEY, "product näme" TEXT, qty INTEGER, note TEXT);
CREATE TABLE big_numbers (id INTEGER PRIMARY KEY, big INTEGER);
INSERT INTO big_numbers (big) VALUES (9223372036854775807), (-9223372036854775808), (9007199254740993);
CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT, level TEXT);
WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x < 2000)
INSERT INTO logs (msg, level) SELECT 'log entry ' || x, CASE x % 3 WHEN 0 THEN 'info' WHEN 1 THEN 'warn' ELSE 'error' END FROM seq;
INSERT INTO users (name, email, age, balance, avatar, meta) VALUES
  ('Alice', 'alice@example.com', 30, 1234.56, X'DEADBEEF', '{"tags":["admin"]}'),
  ('Bob <script>alert(1)</script>', NULL, NULL, -0.5, NULL, NULL),
  ('Chärlie 世界', 'c@example.com', 42, 0, X'00FF00FF00FF', '{"nested":{"a":1}}');
INSERT INTO "order items" ("product näme", qty, note) VALUES ('Widget', 5, 'rush'), ('Gadget''s', 1, NULL);
CREATE VIEW active_logs AS SELECT * FROM logs WHERE level != 'info';
CREATE INDEX idx_logs_level ON logs(level);
CREATE INDEX idx_users_email ON users(email);
-- big_text: >16MiB of export volume so the smoke can prove the desktop export cap.
-- 18,000 rows x ~1KB = ~18MB raw; CSV output lands comfortably past 16,777,216 bytes.
CREATE TABLE big_text (id INTEGER PRIMARY KEY, chunk TEXT NOT NULL);
WITH RECURSIVE big(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM big WHERE x < 18000)
INSERT INTO big_text (chunk) SELECT printf('%06d-', x) || substr(hex(randomblob(512)), 1, 1017) FROM big;
EOF

if [ "$WAL_MODE" = "--wal" ]; then
  # Switch to WAL and force a write so the -wal sidecar materialises on disk.
  sqlite3 "$DB" <<'EOF'
PRAGMA journal_mode = WAL;
CREATE TABLE _wal_probe (x INTEGER);
INSERT INTO _wal_probe VALUES (1);
DROP TABLE _wal_probe;
EOF
  echo "created $DB (WAL mode; $DB-wal present)"
else
  echo "created $DB"
fi
