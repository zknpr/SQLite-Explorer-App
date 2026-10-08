#!/bin/bash
# wait-idle.sh [need_seconds=300] [budget_seconds=3000]
# Exit 0 once the human has been away for >= need seconds AND the screen is not
# locked; exit 1 after budget seconds. Pair it with a batch that re-checks both at
# entry, drives input through guarded-input.sh, captures the window by CGWindowID
# (winid.swift) and installs an EXIT trap that quits the app — an idle window is
# shorter than a tool round-trip, so the batch must run INSIDE the wait, not after
# a notification. env: ISLOCKED = path to the compiled islocked.swift binary.
need="${1:-300}"; budget="${2:-3000}"; waited=0
ISLOCKED="${ISLOCKED:-}"
while [ "$waited" -lt "$budget" ]; do
  idle=$(ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print int($NF/1000000000); exit}')
  locked=0; [ -n "$ISLOCKED" ] && [ -x "$ISLOCKED" ] && locked=$("$ISLOCKED" 2>/dev/null || echo 1)
  if [ "$idle" -ge "$need" ] && [ "$locked" = "0" ]; then echo "idle ${idle}s, unlocked"; exit 0; fi
  sleep 15; waited=$((waited+15))
done
echo "gave up after ${budget}s (last idle ${idle}s locked=${locked})"; exit 1
