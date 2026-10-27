#!/bin/sh
# reset.sh - restore victim.txt to its pristine demo content.
#
# The aonlibc `cat` scenario reads victim.txt. This script (re)creates
# it with a known, harmless line so the demo starts from a clean, repeatable
# state. Run it before a demo, or any time victim.txt has been changed/removed.
#
#   ./reset.sh            reset ./victim.txt
#   ./reset.sh FILE       reset FILE instead
set -eu

FILE="${1:-victim.txt}"
printf '%s' 'Hello from a plain file.' > "$FILE"
echo "reset: $FILE restored to pristine content"
