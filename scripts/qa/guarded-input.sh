#!/bin/bash
# Synthetic input, but only ever into OUR app.
#
# CGEvent clicks carry global screen coordinates: they land on whatever owns that
# pixel, not on the app you meant. So when the human comes back mid-batch and
# switches to their browser, the next "click the toolbar" goes into the browser.
# That has happened — a click intended for Add Column hit a bookmark and navigated
# their tab. Idle time does NOT catch it: synthetic input resets HIDIdleTime, so a
# batch that started safe reads as safe right up until it isn't.
#
# The only sound gate is the frontmost application, re-checked before EVERY event.
#
# usage: guarded-input.sh <click|dclick|rclick|move|scroll|drag> <args...>
#   env: QA_APP   - extended-regex of acceptable frontmost process names.
#                   Defaults to BOTH names this app answers to: System Events
#                   reports the executable ("sqlite-explorer-desktop") as the
#                   frontmost process, while `tell process "SQLite Explorer"`
#                   resolves the bundle display name. Matching only one of them
#                   refuses every event forever, which looks exactly like the
#                   human being present — a guard that cannot pass is worse than
#                   no guard, because it silently skips the QA it was protecting.
#        QACLICK  - path to the compiled click helper
set -euo pipefail

APP="${QA_APP:-^(SQLite Explorer|sqlite-explorer-desktop)$}"
QACLICK="${QACLICK:-}"
if [ -z "$QACLICK" ] || [ ! -x "$QACLICK" ]; then
    echo "guarded-input: set QACLICK to the compiled scripts/qa/click.swift binary" >&2
    exit 2
fi

front=$(osascript -e 'tell application "System Events" to get name of first application process whose frontmost is true' 2>/dev/null || true)

if ! printf '%s' "$front" | grep -Eq "$APP"; then
    # Refuse, loudly, and do not "helpfully" activate the app: stealing focus back
    # from someone who is typing is its own harm, and the batch's later steps would
    # keep fighting them for the keyboard.
    echo "guarded-input: REFUSED — frontmost is '${front:-unknown}', expected /$APP/." >&2
    echo "guarded-input: the human is using the machine; abort the batch rather than retry." >&2
    exit 3
fi

exec "$QACLICK" "$@"
