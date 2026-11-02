#!/bin/bash
# Display a local command's native terminal UI while retaining its output.
source "$(dirname -- "${BASH_SOURCE[0]}")/process_view.sh" || return 1

run_live_output() (
    run_live_output_process "$@"
)

# The decoder starts this body in the background directly, so $! identifies
# the process that owns the cleanup traps rather than an intermediate shell.
run_live_output_process() {
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
}

position_decoder_window() {
    # Give this window a unique title rather than moving another Pocket window.
    local title="Pocket-decoder-${BASHPID}-${RANDOM}"
    printf '\033]0;%s\007' "$title"
    [[ -z ${TMUX:-} ]] || return 0
    [[ -n ${DISPLAY:-} ]] && command -v wmctrl >/dev/null 2>&1 || return 0
    local workarea origin size x y width height window="" attempt
    workarea=$(wmctrl -d 2>/dev/null | awk '$2 == "*" {
        for (i=1; i<=NF; i++) if ($i == "WA:") {print $(i+1), $(i+2); exit}
    }')
    read -r origin size <<< "$workarea"
    [[ $origin =~ ^([0-9]+),([0-9]+)$ ]] || return 0
    x=${BASH_REMATCH[1]}
    y=${BASH_REMATCH[2]}
    [[ $size =~ ^([0-9]+)x([0-9]+)$ ]] || return 0
    width=${BASH_REMATCH[1]}
    height=${BASH_REMATCH[2]}
    ((width > 1 && height > 0)) || return 0
    for ((attempt=0; attempt<10; attempt++)); do
        window=$(wmctrl -l 2>/dev/null | awk -v title="$title" 'index($0,title) {print $1; exit}')
        [[ -z $window ]] || break
        sleep 0.1
    done
    [[ $window =~ ^0x[[:xdigit:]]+$ ]] || return 0
    wmctrl -i -r "$window" -b remove,maximized_vert,maximized_horz 2>/dev/null || true
    wmctrl -i -r "$window" -e "0,$((x + width / 2)),$y,$((width - width / 2)),$height" 2>/dev/null || true
}

run_decoder_view() {
    local library=$1 logfile=$2 status progress_pid=""
    shift 2
    # The separate terminal starts a fresh Bash, so load its PTY/logging helpers.
    source "$library" || return 1
    decoder_cleanup() {
        local exit_status=$?
        trap - EXIT
        trap '' INT TERM HUP
        if [[ -n "$progress_pid" ]]; then
            kill -TERM "$progress_pid" 2>/dev/null || true
            wait "$progress_pid" 2>/dev/null || true
        fi
        exit "$exit_status"
    }
    trap decoder_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    if [[ ${POCKET_VIEW_SEPARATE:-0} == 1 ]]; then
        position_decoder_window
    fi
    printf '\nDecoder: progreso en directo de aircrack-ng.\n'
    run_live_output_process "$logfile" "$@" <&0 &
    progress_pid=$!
    wait "$progress_pid"
    status=$?
    progress_pid=""
    if [[ $status -eq 0 ]] && grep -aFq 'KEY FOUND!' "$logfile"; then
        printf '\n[OK] Contraseña encontrada. Resultado de la herramienta:\n'
        grep -aF 'KEY FOUND!' "$logfile"
    elif [[ $status -eq 0 ]]; then
        printf '\n[AVISO] Análisis finalizado sin una contraseña confirmada.\n'
    else
        printf '\n[AVISO] El decoder terminó con código %s.\n' "$status" >&2
    fi
    printf '\nRegistro guardado: %s\n' "$logfile"
    if [[ ${POCKET_VIEW_SEPARATE:-0} == 1 && -t 0 ]]; then
        read -r -p 'Pulsa Enter para cerrar esta ventana y volver al menú... ' _ || true
    fi
    return "$status"
}

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
    printf 'Se abrirá una ventana con el progreso y el resultado del decoder.\n'
    printf 'Pulsa Ctrl+C para detener el análisis; se conservarán la captura y el registro.\n'
    printf 'Registro privado: %s\n\n' "$logfile"
    # Load helpers by path in the new shell; graphical terminal servers may
    # discard exported Bash functions from their client's environment.
    run_process_view 'Pocket: decoder' "$BASH" -c \
        'source "$1" || exit 1; run_decoder_view "$@"' -- \
        "$(dirname -- "${BASH_SOURCE[0]}")/live_output.sh" \
        "$logfile" aircrack-ng "$capture" -w "$wordlist"
    status=$?
    printf '\nRegistro guardado: %s\n' "$logfile"
    if [[ $status -eq 130 || $status -eq 143 || $status -eq 129 ]]; then
        printf '[AVISO] Análisis interrumpido. La captura se conserva.\n' >&2
    elif [[ $status -ne 0 ]]; then
        printf '[ERROR] La herramienta terminó con código %s. Revisa el mensaje anterior.\n' "$status" >&2
    elif grep -aFq 'KEY FOUND!' "$logfile"; then
        printf '[OK] Contraseña encontrada. Resultado de la herramienta:\n'
        grep -aF 'KEY FOUND!' "$logfile"
    else
        printf '[AVISO] El análisis terminó sin una coincidencia confirmada en el registro.\n'
    fi
    return "$status"
)
