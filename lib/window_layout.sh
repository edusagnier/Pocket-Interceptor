#!/bin/bash
# Presentation only: place the exact window created for a process view.
position_process_window() {
    local slot=$1 title=$2
    printf '\033]0;%s\007' "$title"
    [[ -z ${TMUX:-} ]] || return 0
    if [[ -z ${DISPLAY:-} ]] || ! command -v wmctrl >/dev/null 2>&1; then
        printf '[AVISO] La colocación automática necesita X11 y wmctrl; usa tmux para paneles sin solapamientos.\n' >&2
        return 0
    fi
    local workarea origin size x y width height window="" attempt
    workarea=$(wmctrl -d 2>/dev/null | awk '$2 == "*" {
        for (i=1; i<=NF; i++) if ($i == "WA:") {print $(i+1), $(i+2); exit}
    }')
    read -r origin size <<< "$workarea"
    if [[ ! $origin =~ ^(-?[0-9]+),(-?[0-9]+)$ ]]; then
        printf '[AVISO] No se pudo leer el área de trabajo para colocar esta ventana.\n' >&2
        return 0
    fi
    x=${BASH_REMATCH[1]}
    y=${BASH_REMATCH[2]}
    [[ $size =~ ^([0-9]+)x([0-9]+)$ ]] || return 0
    width=${BASH_REMATCH[1]}
    height=${BASH_REMATCH[2]}
    ((width > 1 && height > 1)) || return 0
    case "$slot" in
        1) width=$((width / 2)); height=$((height / 2)) ;;
        2) x=$((x + width / 2)); width=$((width - width / 2)); height=$((height / 2)) ;;
        3) y=$((y + height / 2)); width=$((width / 2)); height=$((height - height / 2)) ;;
        4) x=$((x + width / 2)); y=$((y + height / 2)); width=$((width - width / 2)); height=$((height - height / 2)) ;;
        *) return 0 ;;
    esac
    for ((attempt=0; attempt<20; attempt++)); do
        window=$(wmctrl -l 2>/dev/null | awk -v title="$title" 'index($0,title) {print $1; exit}')
        [[ -z $window ]] || break
        sleep 0.1
    done
    if [[ ! $window =~ ^0x[[:xdigit:]]+$ ]]; then
        printf '[AVISO] El gestor no permite localizar esta ventana; no se pudo colocar automáticamente.\n' >&2
        return 0
    fi
    wmctrl -i -r "$window" -b remove,maximized_vert,maximized_horz 2>/dev/null || true
    if ! wmctrl -i -r "$window" -e "0,$x,$y,$width,$height" 2>/dev/null; then
        printf '[AVISO] El gestor rechazó colocar esta ventana.\n' >&2
    fi
    return 0
}
