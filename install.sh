#!/bin/bash
test_requirements(){
    
    clear
    sudo apt update -y
    echo "Verifing if requirement software it's installed"
    REQUIRED_FILE="requirements.txt"
    # Verificar si el archivo existe
    if [[ ! -f "$REQUIRED_FILE" ]]; then
        echo "Error: Not found $REQUIRED_FILE"
        exit 1
    fi

    # Leer la lista de paquetes desde el archivo
    REQUIRED_PKGS=($(grep -vE '^\s*#' "$REQUIRED_FILE" | tr '\n' ' '))

    # Verificar que paquetes faltan
    MISSING_PKGS=()
    for pkg in "${REQUIRED_PKGS[@]}"; do
        if ! dpkg -l | grep -qw "$pkg"; then
            MISSING_PKGS+=("$pkg")
        fi
    done

    #Instalar paquetes que no estan installados.
    if [[ ${#MISSING_PKGS[@]} -ne 0 ]]; then
        echo "Installing missing packets: ${MISSING_PKGS[*]}"
        apt update > /dev/null 2>&1 && apt install -y "${MISSING_PKGS[@]}" > /dev/null 2>&1 # En passivo para que no salga por la linea de comandos.
    fi

    FAILED_PKGS=()
    echo "🔍 Checking packages installation..."
    for pkg in "${REQUIRED_PKGS[@]}"; do
        if dpkg -l | grep -qw "$pkg"; then
            echo "✅ $pkg installed correctly"
        else
            echo "❌ $pkg can't get installed"
            FAILED_PKGS+=("$pkg")
        fi
    done

    # Si hay paquetes que no se instalaron correctamente, mostrar error y salir
    if [[ ${#FAILED_PKGS[@]} -ne 0 ]]; then
        echo "Error: The following packages could not be installed: ${FAILED_PKGS[*]}"
        echo "Please try installing them manually with:"
        echo "sudo apt install -y ${FAILED_PKGS[*]}"
        return 1
    fi
    sleep 3

    echo "Configurando scripts..."
    chmod +x netscan.py
    return 0
}

USERID=`id -u`

if [ $USERID == 0 ];then
    test_requirements
else
	echo "Not executed as root"
fi
exit 1