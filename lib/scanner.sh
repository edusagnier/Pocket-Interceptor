#!/bin/bash
# Diagnostics for the network scanner only; no system configuration changes.

SCANNER_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || return 1

run_network_scanner() {
    local status=0
    if ! command -v python3 >/dev/null 2>&1; then
        printf '[ERROR] Escáner: no se encuentra python3.\n' >&2
        status=127
    elif [[ ! -r "$SCANNER_DIRECTORY/netscan.py" ]]; then
        printf '[ERROR] Escáner: netscan.py no existe o no se puede leer.\n' >&2
        status=1
    else
        python3 "$SCANNER_DIRECTORY/netscan.py"
        status=$?
        case "$status" in
            0) ;;
            130) printf '[AVISO] Escáner cancelado por el usuario.\n' >&2 ;;
            *) printf '[ERROR] El escáner terminó con código %s; revisa el mensaje anterior.\n' "$status" >&2 ;;
        esac
    fi
    # The main menu clears the screen on its next iteration.
    if [[ -t 0 ]]; then
        read -r -p 'Pulsa Enter para volver al menú... ' _ || true
    fi
    return "$status"
}
