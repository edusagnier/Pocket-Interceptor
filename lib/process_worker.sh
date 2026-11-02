#!/bin/bash
# Invoked only with a private coordination directory and separate argv entries.
directory=$1
slot=$2
window_title=$3
shift 3
mkdir "$directory/claimed" 2>/dev/null || exit 0
printf '%s\n' "$$" > "$directory/pid.new"
mv -- "$directory/pid.new" "$directory/pid"
child=""
finish() {
    local status=$?
    trap - EXIT
    trap '' INT TERM HUP
    if [[ -n "$child" ]]; then
        kill -TERM "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    printf '%s\n' "$status" > "$directory/status.new"
    mv -- "$directory/status.new" "$directory/status"
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# The decoder uses this to keep its result visible only in a separate view.
export POCKET_VIEW_SEPARATE=1
if source "$(dirname -- "${BASH_SOURCE[0]}")/window_layout.sh"; then
    position_process_window "$slot" "$window_title"
fi
"$@" <&0 &
child=$!
wait "$child"
status=$?
child=""
exit "$status"
