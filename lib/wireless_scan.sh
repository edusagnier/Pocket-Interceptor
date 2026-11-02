#!/bin/bash
# Passive discovery; verify the actual interface, not its name suffix.
source "$(dirname -- "${BASH_SOURCE[0]}")/process_view.sh" || return 1

WIRELESS_SCAN_FILE=""

wireless_scan_error() {
    printf '[ERROR] %s\n' "$1" >&2
    if [[ -t 0 ]]; then
        read -r -p 'Pulsa Enter para volver al menú... ' _ || true
    fi
}

wireless_scan_command() (
    # Keep the scanner's diagnostics outside the disposable terminal window.
    local error_log=$1
    shift
    umask 077
    "$@" 2>"$error_log"
)

scan_wireless_networks() {
    local interface=$1
    local output_directory=$2
    local tool scan_directory status info error_log
    WIRELESS_SCAN_FILE=""
    if [[ -z "$interface" ]]; then
        wireless_scan_error 'No se ha seleccionado una interfaz para el escaneo.'
        return 1
    fi
    for tool in airodump-ng timeout iw; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            wireless_scan_error "No se encuentra $tool en PATH."
            return 127
        fi
    done
    info=$(iw dev "$interface" info 2>&1) || {
        wireless_scan_error "La interfaz $interface no está disponible: $info"
        return 1
    }
    if ! grep -Eq '^[[:space:]]*type monitor[[:space:]]*$' <<< "$info"; then
        wireless_scan_error "$interface no está en modo monitor. Vuelve a activar el modo monitor desde el menú."
        return 1
    fi
    # Read the mode only. airmon-ng handles activation when the user changes
    # mode; scanning must not introduce extra link up/down operations.
    if ! mkdir -p -- "$output_directory"; then
        wireless_scan_error 'No se puede preparar el directorio de resultados.'
        return 1
    fi
    scan_directory=$(umask 077; mktemp -d "$output_directory/discovery_XXXXXXXX") || {
        wireless_scan_error 'No se puede crear el directorio privado del escaneo.'
        return 1
    }
    error_log="$scan_directory/scan.stderr.log"
    printf '\nBuscando redes durante 10 segundos...\n'
    printf 'Registro de diagnóstico: %s\n' "$error_log"
    run_process_view 'Pocket: redes' wireless_scan_command "$error_log" \
        timeout --foreground 10 airodump-ng -w "$scan_directory/networks" \
        --output-format csv "$interface" --ignore-negative-one --band abg
    status=$?
    # GNU timeout reports 124 when the requested observation period is complete.
    case "$status" in
        0|124) ;;
        130) wireless_scan_error 'Escaneo cancelado por el usuario.'; return 130 ;;
        *)
            if [[ -s "$error_log" ]]; then
                printf '\nDiagnóstico del escáner (últimas 40 líneas):\n' >&2
                tail -n 40 -- "$error_log" >&2
                if grep -Eq 'ioctl\(SIOCSIFFLAGS\)|Failed initializing wireless card|RTNETLINK.*Protocol error' "$error_log"; then
                    printf '[DIAGNÓSTICO] La herramienta no ha podido activar o inicializar %s. Detectar modo monitor no garantiza que el adaptador esté operativo.\n' "$interface" >&2
                fi
            elif [[ ! -f "$error_log" ]]; then
                printf '[DIAGNÓSTICO] La vista terminó antes de ejecutar el escáner.\n' >&2
            else
                printf '[DIAGNÓSTICO] La herramienta no escribió detalles en stderr.\n' >&2
            fi
            wireless_scan_error "El escaneo terminó con código $status. Registro: $error_log"
            return "$status"
            ;;
    esac
    if [[ ! -f "$scan_directory/networks-01.csv" || ! -r "$scan_directory/networks-01.csv" || ! -s "$scan_directory/networks-01.csv" ]]; then
        wireless_scan_error 'El escaneo no generó un CSV legible con resultados.'
        return 1
    fi
    WIRELESS_SCAN_FILE="$scan_directory/networks-01.csv"
    return 0
}
