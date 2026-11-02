#!/bin/bash
# Independent views with an acknowledged start and an inline fallback.
PROCESS_VIEW_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

run_process_view() (
    local title=$1
    shift
    local directory launcher="" worker="" status=1 line attempt
    local -a launch=()
    if [[ ${POCKET_TERMINAL_MODE:-auto} != inline ]]; then
        if [[ -n ${TMUX:-} ]] && command -v tmux >/dev/null 2>&1; then
            launch=(tmux)
        elif [[ -n ${DISPLAY:-}${WAYLAND_DISPLAY:-} ]]; then
            if command -v gnome-terminal >/dev/null 2>&1; then
                launch=(gnome-terminal --wait --window --title="$title" --)
            elif command -v x-terminal-emulator >/dev/null 2>&1; then
                launch=(x-terminal-emulator -e)
            fi
        fi
    fi
    if [[ ${#launch[@]} -eq 0 ]]; then
        printf '[INFO] %s: en esta terminal.\n' "$title"
        trap '[[ -z "$worker" ]] || { kill -TERM "$worker" 2>/dev/null; wait "$worker" 2>/dev/null; }' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        trap 'exit 129' HUP
        "$@" <&0 &
        worker=$!
        wait "$worker"
        status=$?
        worker=""
        return "$status"
    fi
    directory=$(umask 077; mktemp -d) || return 1
    # Bash workers can also run the PTY/logging wrapper used by the decoder.
    if declare -F "$1" >/dev/null; then export -f "$1"; fi
    view_cleanup() {
        trap - EXIT
        if [[ -r "$directory/pid" ]]; then
            read -r worker < "$directory/pid"
        fi
        if [[ -n "$worker" ]]; then
            kill -TERM "$worker" 2>/dev/null || true
            wait "$worker" 2>/dev/null || true
        fi
        [[ -z "$launcher" ]] || { kill -TERM "$launcher" 2>/dev/null || true; wait "$launcher" 2>/dev/null || true; }
        rm -f -- "$directory/pid" "$directory/pid.new" "$directory/status" "$directory/status.new"
        rmdir -- "$directory/claimed" "$directory" 2>/dev/null || true
    }
    trap view_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    if [[ ${launch[0]} == tmux ]]; then
        printf -v line '%q ' "$BASH" "$PROCESS_VIEW_DIRECTORY/process_worker.sh" "$directory" "$@"
        tmux split-window -h -d "$line" &
    else
        "${launch[@]}" "$BASH" "$PROCESS_VIEW_DIRECTORY/process_worker.sh" "$directory" "$@" &
    fi
    launcher=$!
    # A successful launcher exit does not prove that its window ran the command.
    for ((attempt=0; attempt<30; attempt++)); do
        [[ ! -f "$directory/pid" ]] || break
        sleep 0.1
    done
    if [[ ! -f "$directory/pid" ]]; then
        # Claim atomically: a delayed terminal must never start a second command.
        if mkdir "$directory/claimed" 2>/dev/null; then
            printf '[AVISO] No se pudo abrir %s; continuando en esta terminal.\n' "$title" >&2
            "$@" <&0 &
            worker=$!
            wait "$worker"
            status=$?
            worker=""
            return "$status"
        fi
        # A worker claimed the command but disappeared before announcing its PID.
        for ((attempt=0; attempt<10; attempt++)); do
            [[ ! -f "$directory/pid" ]] || break
            sleep 0.1
        done
        if [[ ! -f "$directory/pid" ]]; then
            printf '[ERROR] La vista de %s no confirmó su inicio.\n' "$title" >&2
            return 1
        fi
    fi
    while [[ ! -f "$directory/status" ]]; do
        if [[ -r "$directory/pid" ]]; then
            read -r worker < "$directory/pid"
            if ! kill -0 "$worker" 2>/dev/null && [[ ! -f "$directory/status" ]]; then
                printf '[ERROR] Se cerró la vista de %s antes de terminar.\n' "$title" >&2
                return 1
            fi
        fi
        sleep 0.1
    done
    read -r status < "$directory/status"
    # The command has finished. Do not signal a potentially reused PID.
    rm -f -- "$directory/pid"
    worker=""
    return "$status"
)
