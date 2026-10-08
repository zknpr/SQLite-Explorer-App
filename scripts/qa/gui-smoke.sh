#!/usr/bin/env bash
# Idle-gated GUI smoke runner.
#
# Driving synthetic keystrokes into a Mac someone is using can type into THEIR
# apps — a browser, a mail composer — so every input step here is gated twice:
# the human must have been idle for MIN_IDLE seconds, and our own window must be
# frontmost. Either check failing aborts the run instead of pressing on, and the
# guard is re-checked before each step, so a human returning mid-run stops it.
#
# Captures are cropped to our own window rect, never the whole screen: a full
# screenshot of someone's desktop is their private content, not test evidence.
#
#   gui-smoke.sh [min_idle_seconds]     (default 150)
set -uo pipefail

APP_NAME="sqlite-explorer-desktop"
MIN_IDLE="${1:-150}"
OUT="${GUI_SMOKE_OUT:-/tmp/qa-gui-smoke}"
mkdir -p "$OUT"
REPORT="$OUT/report.md"
: > "$REPORT"

pass=0; fail=0; skipped=0

log()  { printf '%s\n' "$*" >> "$REPORT"; printf '%s\n' "$*"; }
ok()   { pass=$((pass+1));    log "- PASS  $1"; }
bad()  { fail=$((fail+1));    log "- FAIL  $1${2:+ — $2}"; }
skip() { skipped=$((skipped+1)); log "- SKIP  $1${2:+ — $2}"; }

human_idle() {
  local ns
  ns=$(ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print $NF; exit}' | tr -d '|} ')
  [ -n "$ns" ] || { echo 0; return; }
  echo $(( ns / 1000000000 ))
}

frontmost() {
  osascript -e 'tell application "System Events" to get name of first process whose frontmost is true' 2>/dev/null
}

# Epoch seconds of the last input WE synthesised. The HID idle timer counts our own
# CGEvent/System-Events keystrokes too, so a naive "idle >= MIN_IDLE" gate disarms
# itself the moment it types anything — the first run of this script passed 12 checks
# and then refused every remaining step because it had just typed a path itself.
MY_LAST_INPUT=""
note_input() { MY_LAST_INPUT=$(date +%s); }

# The gate. Returns non-zero when it is not safe to synthesise input.
#
# Before any input of our own, require a genuinely idle machine. After that, the
# question is not "is the timer high" but "did anything reset it MORE RECENTLY than
# our own last keystroke" — if so, a human touched the keyboard and we stop.
guard() {
  local idle now mine_ago
  idle=$(human_idle)
  if [ -z "$MY_LAST_INPUT" ]; then
    if [ "$idle" -lt "$MIN_IDLE" ]; then
      log ""
      log "**ABORTED: a human is at the keyboard (idle ${idle}s < ${MIN_IDLE}s).** No input was sent."
      return 1
    fi
  else
    now=$(date +%s); mine_ago=$(( now - MY_LAST_INPUT ))
    if [ "$(( idle + 3 ))" -lt "$mine_ago" ]; then
      log ""
      log "**ABORTED: a human touched the keyboard** (idle ${idle}s, but our own last input was ${mine_ago}s ago). Stopping rather than typing into their apps."
      return 1
    fi
  fi
  local fg; fg=$(frontmost)
  if [ "$fg" != "$APP_NAME" ]; then
    osascript -e "tell application \"System Events\" to tell process \"$APP_NAME\" to set frontmost to true" >/dev/null 2>&1
    sleep 1
    fg=$(frontmost)
    [ "$fg" = "$APP_NAME" ] || { log ""; log "**ABORTED: could not focus our own window (frontmost=$fg).**"; return 1; }
  fi
  return 0
}

win_rect() { osascript -e "tell application \"System Events\" to tell process \"$APP_NAME\" to get {position, size} of window 1" 2>/dev/null; }

# Crop to our window only — never the desktop.
shot() {
  local name="$1" r x y w h
  r=$(win_rect) || return 1
  x=$(echo "$r" | cut -d, -f1 | tr -d ' '); y=$(echo "$r" | cut -d, -f2 | tr -d ' ')
  w=$(echo "$r" | cut -d, -f3 | tr -d ' '); h=$(echo "$r" | cut -d, -f4 | tr -d ' ')
  [ -n "$x" ] && [ -n "$w" ] || return 1
  screencapture -x -R"${x},${y},${w},${h}" "$OUT/$name.png" 2>/dev/null
}

win_count() { osascript -e "tell application \"System Events\" to tell process \"$APP_NAME\" to get count of windows" 2>/dev/null; }
win_title() { osascript -e "tell application \"System Events\" to tell process \"$APP_NAME\" to get name of window 1" 2>/dev/null; }

menu_click() { # menu_click <top menu> <item>
  osascript -e "tell application \"System Events\" to tell process \"$APP_NAME\" to click menu item \"$2\" of menu 1 of menu bar item \"$1\" of menu bar 1" >/dev/null 2>&1
  note_input
}

# Type a path into a native open/save panel via Go-to-folder.
panel_path() { # panel_path <path>
  osascript >/dev/null 2>&1 <<EOF
tell application "System Events"
  keystroke "g" using {command down, shift down}
  delay 1.2
  keystroke "$1"
  delay 0.8
  key code 36
  delay 1.2
  key code 36
end tell
EOF
  note_input
  sleep 3
}

key() { # key <keystroke-body>  e.g. '"s" using {command down}'
  osascript -e "tell application \"System Events\" to keystroke $1" >/dev/null 2>&1
  note_input
}

log "# GUI smoke — $(date '+%Y-%m-%d %H:%M:%S')"
log ""
log "Gate: human idle >= ${MIN_IDLE}s and our window frontmost, re-checked before every input step."
log "Captures are cropped to our own window rect. Evidence in \`$OUT\`."
log ""

# ---------------------------------------------------------------- boot
if ! pgrep -qf "$APP_NAME"; then
  bad "app is running" "start it with: cd src-tauri && cargo run --features tauri/custom-protocol"
  log ""; log "Totals: $pass pass, $fail fail, $skipped skip"; exit 1
fi
ok "app process is running"

t=$(win_title)
case "$t" in
  *"SQLite Explorer"*) ok "window titled ($t)" ;;
  *) bad "window title" "got '$t'" ;;
esac
shot 01-boot

# The launch-blocking regression: the bridge failing at init rendered this text
# and nothing else. Assert the UI is actually there instead.
if osascript -e "tell application \"System Events\" to tell process \"$APP_NAME\" to get value of static text 1 of window 1" 2>/dev/null | grep -qi "bridge missing"; then
  bad "desktop bridge injected" "page reports 'Desktop bridge missing'"
else
  ok "desktop bridge injected (no 'bridge missing' text)"
fi

# ---------------------------------------------------------------- menus (no input needed)
FILE_ITEMS=$(osascript -e "tell application \"System Events\" to tell process \"$APP_NAME\" to get name of every menu item of menu 1 of menu bar item \"File\" of menu bar 1" 2>/dev/null)
for want in "Open Database…" "Export Database…" "Open in New Window" "Save" "Refresh From Disk" "Open Recent"; do
  case "$FILE_ITEMS" in *"$want"*) ok "File menu has '$want'" ;; *) bad "File menu missing '$want'" ;; esac
done
VIEW_ITEMS=$(osascript -e "tell application \"System Events\" to tell process \"$APP_NAME\" to get name of every menu item of menu 1 of menu bar item \"View\" of menu bar 1" 2>/dev/null)
case "$VIEW_ITEMS" in *"Theme"*) ok "View menu has Theme submenu" ;; *) bad "View menu missing Theme" ;; esac
case "$VIEW_ITEMS" in *"SQL Console"*) ok "View menu has SQL Console" ;; *) bad "View menu missing SQL Console" ;; esac

# ---------------------------------------------------------------- open a database
if guard; then
  menu_click "File" "Open Database…"; sleep 2
  panel_path "/tmp/qa-test.db"
  t=$(win_title)
  case "$t" in
    *qa-test*) ok "opened /tmp/qa-test.db (title: $t)" ;;
    *) bad "open did not take" "title still '$t'" ;;
  esac
  shot 02-opened
else
  skip "open a database" "guard refused"
fi

# ------------------------------------------------- export the whole database
# Ordered BEFORE the multi-database steps on purpose: the first version of this
# script exported after Cmd+W had closed a tab, so "the active database" was
# whatever survived, and a 0-byte result was indistinguishable from exporting the
# empty boot placeholder. Export the database we just opened, and assert its
# CONTENT so an empty-but-valid file cannot pass.
if guard; then
  rm -f /tmp/qa-export-out.db
  menu_click "File" "Export Database…"; sleep 2
  panel_path "/tmp/qa-export-out.db"
  sleep 4
  if [ -s /tmp/qa-export-out.db ]; then
    rows=$(sqlite3 /tmp/qa-export-out.db "SELECT count(*) FROM users;" 2>/dev/null)
    integ=$(sqlite3 /tmp/qa-export-out.db "PRAGMA integrity_check;" 2>/dev/null)
    if [ "$integ" = "ok" ] && [ "${rows:-0}" -ge 3 ]; then
      ok "Export Database… wrote the open database ($(stat -f%z /tmp/qa-export-out.db) bytes, $rows users rows)"
    else
      bad "exported file is not the open database" "integrity='$integ' users rows='$rows'"
    fi
  else
    bad "Export Database… produced no bytes" "dest exists but empty, or nothing written"
  fi
  if ls /tmp/.sqlite-export-* >/dev/null 2>&1; then bad "export left a temp dir behind"; else ok "export left no temp dir"; fi
else
  skip "export database" "guard refused"
fi

# ---------------------------------------------------------------- edit + save to disk
if guard; then
  BEFORE=$(sqlite3 /tmp/qa-test.db "SELECT name FROM users WHERE id=1;")
  # Focus the grid and edit the first editable cell is layout-dependent; instead
  # drive the SQL console, which is deterministic and exercises the same save path.
  key '"k" using {command down, shift down}'; sleep 2
  osascript -e "tell application \"System Events\" to keystroke \"UPDATE users SET name='GuiSmoke' WHERE id=1;\"" >/dev/null 2>&1
  note_input
  sleep 1
  osascript -e 'tell application "System Events" to key code 36 using {command down}' >/dev/null 2>&1
  note_input
  sleep 3
  MID=$(sqlite3 /tmp/qa-test.db "SELECT name FROM users WHERE id=1;")
  if [ "$MID" = "$BEFORE" ]; then
    ok "console mutation is pending, not yet on disk (still '$MID')"
  else
    bad "pending-until-save contract" "disk changed before save: '$BEFORE' -> '$MID'"
  fi
  t=$(win_title)
  case "$t" in *Edited*) ok "title shows unsaved marker ($t)" ;; *) bad "no unsaved marker in title" "got '$t'" ;; esac
  key '"s" using {command down}'; sleep 3
  AFTER=$(sqlite3 /tmp/qa-test.db "SELECT name FROM users WHERE id=1;")
  if [ "$AFTER" = "GuiSmoke" ]; then ok "Cmd+S committed to disk (now '$AFTER')"; else bad "Cmd+S did not persist" "disk shows '$AFTER'"; fi
  sqlite3 /tmp/qa-test.db "UPDATE users SET name='$BEFORE' WHERE id=1;" 2>/dev/null
  shot 03-saved
else
  skip "edit + save" "guard refused"
fi

# ---------------------------------------------------------------- clipboard (highest-risk item)
if guard; then
  osascript -e 'set the clipboard to "SENTINEL-BEFORE-COPY"' >/dev/null 2>&1
  key '"a" using {command down}'; sleep 1     # select-all in the grid
  key '"c" using {command down}'; sleep 1.5
  CB=$(pbpaste 2>/dev/null | head -c 200)
  if [ "$CB" = "SENTINEL-BEFORE-COPY" ]; then
    bad "Cmd+C copies grid data" "clipboard unchanged — the page preventDefaults and the native Copy never runs"
  elif [ -n "$CB" ]; then
    ok "Cmd+C put data on the clipboard ($(printf '%s' "$CB" | wc -c | tr -d ' ') bytes)"
  else
    bad "Cmd+C copies grid data" "clipboard empty"
  fi
else
  skip "clipboard copy" "guard refused"
fi

# ------------------------------------------------- pointer gestures and theming
# NOT DONE HERE, deliberately. Screen-region hashing is the wrong instrument for
# these: it reported three "failures" that were all its own fault — a 3-row table
# has nothing to scroll, a guessed coordinate misses the resize handle, and the
# top 60 points it sampled were the native title bar, which the page cannot
# repaint. Scrolling, column resize and all five palettes are asserted precisely
# in the DOM instead (see gui-verification-report.md): scrollTop 0 -> 400 across
# 64 virtualised rows, the dragged column 222 -> 360 with its neighbours
# untouched, and data-theme taking each of nord/light/high-contrast/solarized/dark.
# What only THIS harness can reach — native menus, panels, accelerators, the
# clipboard, real windows, and the filesystem — is what it tests.

# ---------------------------------------------------------------- second database + tabs
if guard; then
  menu_click "File" "Open Database…"; sleep 2
  panel_path "/tmp/qa-wal.db"
  t=$(win_title)
  case "$t" in *qa-wal*) ok "second database opened ($t)" ;; *) bad "second open did not take" "title '$t'" ;; esac
  shot 04-two-dbs
  # Cmd+1 / Cmd+2 must switch by physical digit key (layout-independent).
  osascript -e 'tell application "System Events" to key code 18 using {command down}' >/dev/null 2>&1; note_input; sleep 2
  t1=$(win_title)
  osascript -e 'tell application "System Events" to key code 19 using {command down}' >/dev/null 2>&1; note_input; sleep 2
  t2=$(win_title)
  if [ "$t1" != "$t2" ]; then ok "Cmd+1 / Cmd+2 switch databases ($t1 <-> $t2)"; else bad "Cmd+1/Cmd+2 did not switch" "both '$t1'"; fi
  shot 05-switched
  # Cmd+W must close the TAB while two are open, not the window.
  W_BEFORE=$(win_count)
  key '"w" using {command down}'; sleep 2
  W_AFTER=$(win_count)
  if [ "$W_AFTER" = "$W_BEFORE" ]; then ok "Cmd+W closed a tab, not the window (windows still $W_AFTER)"; else bad "Cmd+W closed the window" "$W_BEFORE -> $W_AFTER"; fi
else
  skip "second database, tabs, Cmd+W" "guard refused"
fi

# ---------------------------------------------------------------- second window
if guard; then
  W_BEFORE=$(win_count)
  menu_click "File" "Open in New Window"; sleep 3
  W_AFTER=$(win_count)
  if [ "${W_AFTER:-0}" -gt "${W_BEFORE:-0}" ]; then ok "Open in New Window created a window ($W_BEFORE -> $W_AFTER)"; else bad "no second window" "$W_BEFORE -> $W_AFTER"; fi
  shot 06-second-window
else
  skip "second window" "guard refused"
fi

log ""
log "Totals: **$pass pass, $fail fail, $skipped skip**"
log ""
log "Not covered here: real Finder drag-and-drop (the OS refuses synthesised drags"
log "between processes), whether a theme LOOKS right (mechanical repaint is checked"
log "above; taste is not), and Dock right-click ▸ Quit, which bypasses the unsaved"
log "prompt by design — tao exposes no hook, so it is a documented limitation."
[ "$fail" -eq 0 ]
