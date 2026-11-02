#!/bin/bash
# Display a local command's native terminal UI while retaining its output.
source "$(dirname -- "${BASH_SOURCE[0]}")/process_view.sh" || return 1

run_live_output() (
    local logfile=$1
    shift
    local command_line viewer_pid="" status
    if ! command -v script >/dev/null 2>&1; then
        printf '[ERROR] Falta script (paquete util-linux) para mostrar la pantalla en directo.\n' >&2
        return 127
    fi
    # script uses SHELL for --command; %q must be interpreted by Bash.
    printf -v command_line '%q ' "$@"
    # Replace script's intermediate shell with the actual command. Its signal
    # cleanup then targets that command rather than leaving it behind a shell.
    command_line="exec $command_line"
    live_output_cleanup() {
        local exit_status=$?
        trap - EXIT
        trap '' INT TERM HUP
        if [[ -n "$viewer_pid" ]]; then
            # Let script terminate its PTY child and restore terminal settings.
            # Do not SIGKILL the viewer before it has performed that cleanup.
            kill -TERM "$viewer_pid" 2>/dev/null || true
            wait "$viewer_pid" 2>/dev/null || true
        fi
        exit "$exit_status"
    }
    trap live_output_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    # Explicit stdin avoids Bash redirecting a background command to /dev/null.
    SHELL="$BASH" script --quiet --return --flush --command "$command_line" "$logfile" <&0 &
    viewer_pid=$!
    wait "$viewer_pid"
    status=$?
    viewer_pid=""
    return "$status"
)

show_handshake_progress() (
    local capture=$1
    local wordlist=$2
    local output_directory=$3
    local logfile status
    if ! command -v aircrack-ng >/dev/null 2>&1; then
        printf '[ERROR] No se encuentra aircrack-ng.\n' >&2
        return 127
    fi
    if [[ ! -f "$capture" || ! -r "$capture" || ! -s "$capture" ]]; then
        printf '[ERROR] La captura no existe, está vacía o no se puede leer: %s\n' "$capture" >&2
        return 1
    fi
    if [[ ! -f "$wordlist" || ! -r "$wordlist" || ! -s "$wordlist" ]]; then
        printf '[ERROR] El diccionario no existe, está vacío o no se puede leer: %s\n' "$wordlist" >&2
        return 1
    fi
    umask 077
    logfile=$(mktemp "$output_directory/result_handshake_XXXXXXXX.txt") || {
        printf '[ERROR] No se puede crear el registro de resultados.\n' >&2
        return 1
    }
    printf '\nAnálisis local del handshake: progreso en directo.\n'
    printf 'La herramienta mostrará su estado; no es un descifrado carácter a carácter.\n'
    printf 'Pulsa Ctrl+C para detener el análisis; se conservarán la captura y el registro.\n'
    printf 'Registro privado: %s\n\n' "$logfile"
    run_process_view 'Pocket: decoder' run_live_output "$logfile" aircrack-ng "$capture" -w "$wordlist"
    status=$?
    printf '\nRegistro guardado: %s\n' "$logfile"
    if [[ $status -eq 130 || $status -eq 143 || $status -eq 129 ]]; then
        printf '[AVISO] Análisis interrumpido. La captura se conserva.\n' >&2
    elif [[ $status -ne 0 ]]; then
        printf '[ERROR] La herramienta terminó con código %s. Revisa el mensaje anterior.\n' "$status" >&2
    elif grep -Fq 'KEY FOUND!' "$logfile"; then
        printf '[OK] La herramienta ha indicado una coincidencia; consulta su resultado.\n'
    else
        printf '[AVISO] El análisis terminó sin una coincidencia confirmada en el registro.\n'
    fi
    return "$status"
)
