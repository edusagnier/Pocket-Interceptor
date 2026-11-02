#!/bin/bash
# Invoked only with a private coordination directory and separate argv entries.
directory=$1
shift
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
"$@" <&0 &
child=$!
wait "$child"
status=$?
child=""
exit "$status"
