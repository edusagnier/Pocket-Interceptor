#!/bin/bash
intro(){
    clear
    echo "________            ______      _____"                                
    echo "___  __ \______________  /________  /_    "                           
    echo "__  /_/ /  __ \  ___/_  //_/  _ \  __/"                               
    echo "_  ____// /_/ / /__ _  ,<  /  __/ /_"                                 
    echo "/_/     \____/\___/ /_/|_| \___/\__/"                                 
    echo""                                                                     
    echo""                                                                     
    echo""                                                                     
    echo "________                             "                                
    echo "_/_____/                              "                               
    echo""                                                                     
    echo""                                                                                                                                    
    echo "________      _____                               _____              "
    echo "____  _/________  /_________________________________  /______________"
    echo " __  / __  __ \  __/  _ \_  ___/  ___/  _ \__  __ \  __/  __ \_  ___/"
    echo "__/ /  _  / / / /_ /  __/  /   / /__ /  __/_  /_/ / /_ / /_/ /  /    "
    echo "/___/  /_/ /_/\__/ \___//_/    \___/ \___/_  .___/\__/ \____//_/     "
    echo "                                          /_/                        "
    sleep 5
}

test_requirements(){
    
    clear
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
    return 0
}

SELECTED_INTERFACE=""

select_interface(){    
    clear

    # Obtener lista de interfaces de red disponibles
    INTERFACES=($(ip -o link show | awk -F': ' '{print $2}'))

     #Verifica si tiene interfaces activas
    if [ ${#INTERFACES[@]} -lt 1 ]; then
    echo "There's no active interfaces."
    exit 1
    fi

    # Mostrar las interfaces disponibles
    echo "Select a network interface:"
    for i in "${!INTERFACES[@]}"; do
        echo "$((i+1)). ${INTERFACES[i]}"
    done

    # Leer la selección del usuario
    read -p "Enter the interface wanted: " CHOICE

    # Validar la entrada
    if [[ ! "$CHOICE" =~ ^[0-9]+$ ]] || ((CHOICE < 1 || CHOICE > ${#INTERFACES[@]})); then
        echo "Selected interface not valid."
        exit 1
    fi

    # Obtener la interfaz seleccionada
    SELECTED_INTERFACE="${INTERFACES[CHOICE-1]}"
    sleep 2
}


monitor_mode(){

 airmon-ng start $SELECTED_INTERFACE; SELECTED_INTERFACE="${SELECTED_INTERFACE}mon"

}

manager_mode(){

 airmon-ng stop "$SELECTED_INTERFACE"

}

menu(){
   
    if ! test_requirements; then
        exit 1
    else
        select_interface
    fi
    
    BOOL_SELECTION=true0


    while $BOOL_SELECTION; do
        
        MODE=$(iwconfig "$SELECTED_INTERFACE" 2>/dev/null | grep -o 'Mode:[^ ]*' | cut -d: -f2)
        clear
        echo "You haved selected the interface: $SELECTED_INTERFACE  in Mode: $MODE"
        echo ""
        echo "+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+"
        echo "|M|e|n|u| |I|n|t|e|r|c|e|p|t|o|r|"
        echo "+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+"
        echo ""
        echo "Network Configuration Menu"
        echo "- - - - - - - - - - - - - - - - - -"
        echo "0. Exit Scipt"
        echo "1. Change Network Interface"
        echo "2. Put Interface In Monitor Mode (Needed for wireless atacks)"
        echo "3. Put Interface In Manager Mode "    
        echo "4. Select wireless network "
        echo "- - - - - - - - - - - - - - - - - -"
        echo ""
        echo "Atacks Menu"
        echo "- - - - - - - - - - - - - - - - - -"
        echo "5. Deauther + Bruteforce (Get inside the Wireless network) "
        echo "6. Fake Capcha (Deauther + Ap Spofing + Phishing Login)"
        echo "7. DoS Attack (Stop the wireless conexions)"
        echo "8. Scan Network (Search Devices + Vulnerabilities)"
        echo "9. Scan Network (Search Devices + Vulnerabilities)"
        echo "- - - - - - - - - - - - - - - - - -"
        echo ""
        echo ""
        read -p "Select the option you want:" SELECTION

        case $SELECTION in
            1) echo ""; select_interface ;;
            2) echo "Changing mode"; monitor_mode;;
            3) echo "Changing mode"; manager_mode ;;
            4) echo ""; ps aux | less ;;
            5) echo ""; curl -s ifconfig.me ;;
            6) echo ""; hostname -I ;;
            7) echo ""; free -h ;;
            8) echo ""; uptime ;;
            9) echo ""; uname -r ;;
            0) echo "👋 Goodbye..."; exit 0 ;;
            *) echo "❌ Not valid option." ;;
        esac
    done

}





USERID=`id -u`

if [ $USERID == 0 ];then
    intro
    menu
else
	echo "Not executed as root"
fi
