#!/bin/bash
# Local educational portal; never calls system network administration tools.

LAB_PORTAL_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || return 1

run_lab_portal() {
    local status
    if ! command -v python3 >/dev/null 2>&1; then
        printf '[ERROR] El portal de laboratorio necesita Python 3.\n' >&2
        return 127
    fi
    if [[ ! -r "$LAB_PORTAL_DIRECTORY/tools/lab_portal.py" ]]; then
        printf '[ERROR] No se encuentra tools/lab_portal.py.\n' >&2
        return 1
    fi
    python3 -B "$LAB_PORTAL_DIRECTORY/tools/lab_portal.py"
    status=$?
    if [[ $status -eq 130 ]]; then
        printf '[AVISO] Portal de laboratorio cancelado.\n' >&2
    elif [[ $status -ne 0 ]]; then
        printf '[ERROR] El portal de laboratorio terminó con código %s.\n' "$status" >&2
    fi
    return "$status"
}
