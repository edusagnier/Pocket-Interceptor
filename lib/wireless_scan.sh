#!/bin/bash
# Passive network discovery in the current terminal. No mode/service changes.

WIRELESS_SCAN_FILE=""

wireless_scan_error() {
    printf '[ERROR] %s\n' "$1" >&2
    if [[ -t 0 ]]; then
        read -r -p 'Pulsa Enter para volver al menú... ' _ || true
    fi
}

scan_wireless_networks() {
    local interface=$1
    local output_directory=$2
    local tool scan_directory status
    WIRELESS_SCAN_FILE=""
    if [[ -z "$interface" ]]; then
        wireless_scan_error 'No se ha seleccionado una interfaz para el escaneo.'
        return 1
    fi
    for tool in airodump-ng timeout; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            wireless_scan_error "No se encuentra $tool en PATH."
            return 127
        fi
    done
    if ! mkdir -p -- "$output_directory"; then
        wireless_scan_error 'No se puede preparar el directorio de resultados.'
        return 1
    fi
    scan_directory=$(umask 077; mktemp -d "$output_directory/discovery_XXXXXXXX") || {
        wireless_scan_error 'No se puede crear el directorio privado del escaneo.'
        return 1
    }
    printf '\nBuscando redes durante 10 segundos en esta terminal...\n'
    # Keep arguments separate; do not launch a GUI terminal or construct shell code.
    timeout --foreground 10 airodump-ng -w "$scan_directory/networks" \
        --output-format csv "$interface" --ignore-negative-one --band abg
    status=$?
    # GNU timeout reports 124 when the requested observation period is complete.
    case "$status" in
        0|124) ;;
        130) wireless_scan_error 'Escaneo cancelado por el usuario.'; return 130 ;;
        *) wireless_scan_error "El escaneo terminó con código $status. Revisa el mensaje anterior."; return "$status" ;;
    esac
    if [[ ! -f "$scan_directory/networks-01.csv" || ! -r "$scan_directory/networks-01.csv" || ! -s "$scan_directory/networks-01.csv" ]]; then
        wireless_scan_error 'El escaneo no generó un CSV legible con resultados.'
        return 1
    fi
    WIRELESS_SCAN_FILE="$scan_directory/networks-01.csv"
    return 0
}
