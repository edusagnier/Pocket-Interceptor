#!/usr/bin/python3

import subprocess
import re
import requests
import os
from time import sleep
from urllib.parse import quote

# Lee la clave de la API de NVD desde la variable de entorno.
NVD_API_KEY = os.getenv('NVD_API_KEY', '')

# Mapeo de nombres de servicios para la búsqueda de CVEs.
SERVICE_MAPPING = {
    'ssh': 'OpenSSH',
    'http': 'Apache HTTP Server',
    'https': 'Apache HTTP Server',  
    'smtp': 'Postfix',
    'smtps': 'Postfix',  
    'pop3': 'Dovecot',
    'pop3s': 'Dovecot',       
    'imap': 'Dovecot',
    'imaps': 'Dovecot',        
    'ftp': 'vsftpd',
    'telnet': 'Telnet',
    'dns': 'BIND',
    'mysql': 'MySQL',
    'postgresql': 'PostgreSQL',
    'nfs': 'NFS Server',
    'ldap': 'OpenLDAP',
    'snmp': 'Net-SNMP',
}
def netdisc():
    try:
        print("\nRunning network discovery...")
        # Llama al otro scropt
        subprocess.run(["bash", "netdisc.sh"], check=True)
        print("Network discovery completed. Results saved in scan.txt")
    # Manejo de errores si el script falla o no se encuentra
    except subprocess.CalledProcessError as e:
        print(f"Error during network discovery: {e}")
    except FileNotFoundError:
        print("Error: netdisc.sh script not found")

# Función para extraer la parte principal de la versión de un software
def get_clean_version(version):
    # Busca un patrón de versión principal (números y un punto)
    match = re.search(r'(\d+\.\d+)', version)
    # Devuelve la parte principal si la encuentra, de lo contrario, devuelve la versión original
    return match.group(1) if match else version

# Función principal para verificar CVEs de un servicio y su versión usando la API de NVD
def check_cve_nvd(service, version):
    # Obtiene el nombre del producto estándar para la búsqueda
    product = SERVICE_MAPPING.get(service.lower(), service)
    # Obtiene una versión "limpia" para la búsqueda
    version_clean = get_clean_version(version)

    try:
        # URL y parámetros para la consulta a la API de NVD
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        query = f"{product} {version_clean}"
        params = {
            'keywordSearch': query,
            'resultsPerPage': 20
        }
        headers = {}
        if NVD_API_KEY:
            headers['apiKey'] = NVD_API_KEY
        sleep(1)
        # Ppetición a la API y procesa la respuesta JSON para extraer las CVEs
        response = requests.get(url, params=params, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()

        cves = []
        # Itera sobre las vulnerabilidades encontradas y formatea la información de la CVE
        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', '')
            descriptions = [d['value'] for d in cve.get('descriptions', [])
                            if d.get('lang') == 'en']
            description = descriptions[0] if descriptions else 'No description'
            cves.append(f"{cve_id}: {description[:120]}...")
        
        # Limita el número de CVEs mostrados para legibilidad
        return cves[:5] 

    # Errores de la petición a la API o del procesamiento de los datos
    except requests.exceptions.RequestException as e:
        print(f"NVD API request failed: {str(e)}")
        return []


# Función para mostrar los resultados del escaneo
def results(devices, output_file=None):
    output = []

    if not devices:
        msg = "\nNo devices found."
        print(msg)
        output.append(msg)
    # Si se encontraron dispositivos
    else:
        msg = "\nDevices Found:\n"
        print(msg)
        output.append(msg)

        for ip, ports in devices.items():
            ip_msg = f" IP: {ip}"
            print(ip_msg)
            output.append(ip_msg)
            # Itera sobre los puertos abiertos y los servicios encontrados en cada dispositivo
            for port, service, version in ports:
                port_msg = f"  -> {port}: {service} (Version: {version})"
                print(port_msg)
                output.append(port_msg)
                # Busca y muestra las CVEs para el servicio y la versión actuales
                cves = check_cve_nvd(service, version)
                if cves:
                    cve_msg = "    CVEs Found:"
                    print(cve_msg)
                    output.append(cve_msg)
                    for cve in cves:
                        cve_item = f"      - {cve}"
                        print(cve_item)
                        output.append(cve_item)
                else:
                    no_cve = "    No known CVEs found."
                    print(no_cve)
                    output.append(no_cve)


# Función para realizar un escaneo de red utilizando la herramienta Nmap.
def netscan(network):
    print(f"\nScanning network: {network} (this may take several minutes)...\n")
    try:
        # Comando Nmap para escanear la red y detectar versiones de servicios
        command = [
            "nmap", "-sV", "-T4", "--min-rate", "500",
            "--max-retries", "2", "-Pn", "-p1-10000", network
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=3600)
        # Parsea la salida de Nmap para obtener la información de los dispositivos
        return parse_nmap_results(result.stdout)
    # Maneja los errores de tiempo de espera durante la ejecución de Nmap
    except subprocess.TimeoutExpired:
        print("Scan timed out after 1 hour")
        return {}

# Función para escanear un único dispositivo utilizando Nmap
def devscan(ip_address):
    print(f"\nScanning device: {ip_address}\n")
    try:
        # Comando Nmap para escanear un dispositivo específico y detectar versiones de servicios
        command = [
            "nmap", "-sV", "-T4", "-Pn", "-p-",
            "--version-intensity", "7", ip_address
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        # Parsea la salida de Nmap para obtener la información del dispositivo
        return parse_nmap_results(result.stdout)
    # Maneja los errores de tiempo de espera o cualquier otra excepción durante la ejecución de Nmap
    except subprocess.TimeoutExpired:
        print("Scan timed out after 30 minutes")
        return {ip_address: []}

# Función para analizar la salida de texto de Nmap y extraer información sobre los puertos abiertos, servicios y versiones
def parse_nmap_results(nmap_output):
    devices = {}
    # Define expresiones regulares para encontrar la información relevante en la salida de Nmap
    port_pattern = r"(\d+)/tcp\s+open\s+([\w\-]+)\s+(.+?)(?:\n|$)"
    ip_pattern = r"Nmap scan report for ([\d\.]+)"

    current_ip = None
    # Itera sobre cada línea de la salida de Nmap
    for line in nmap_output.splitlines():
        # Busca la línea que indica el inicio del reporte para una nueva IP
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            current_ip = ip_match.group(1)
            if current_ip not in devices:
                devices[current_ip] = []
            continue
        # Si se ha encontrado una IP, busca las líneas que contienen información sobre los puertos abiertos
        if current_ip:
            port_match = re.search(port_pattern, line)
            if port_match:
                port, service, full_version = port_match.groups()
                # Extrae la versión principal del servicio.
                version = extract_version(full_version)
                devices[current_ip].append((port, service, version))

    return devices

# Función para extraer la versión principal de una cadena de versión más detallada
def extract_version(full_version):
    version_patterns = [
        # Patrones para versiones
        r"(\d+\.\d+\.\d+[a-zA-Z0-9\-\.]*)",  # 1.2.3
        r"(\d+\.\d+[a-zA-Z0-9\-\.]*)",       # 1.2
        r"(\d+[a-zA-Z0-9\-\.]*)"             # 1
    ]
    # Intenta encontrar la versión utilizando los patrones 
    for pattern in version_patterns:
        match = re.search(pattern, full_version)
        if match:
            return match.group(0)
    # Devuelve "unknown" si no se puede extraer una versión
    return "unknown" 

# Menú principal del script
def menu():
    while True:
        print("\nNetwork Scanner Menu:")
        print("0. Exit")
        print("1. Scan the entire network")
        print("2. Scan a single device")
        print("3. Run network discovery")

        choice = input("\nEnter your choice (0/1/2/3): ").strip()

        if choice == "0":
            print("Exiting...")
            exit(0)
        elif choice == "1":
            network = input("\nEnter network to scan (e.g., 192.168.1.0/24): ").strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$", network):
                devices = netscan(network)
                results(devices)
            else:
                print("Invalid network format!")
        elif choice == "2":
            ip_address = input("\nEnter IP address to scan: ").strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
                devices = devscan(ip_address)
                results(devices)
            else:
                print("Invalid IP address format!")
        elif choice == "3":
            netdisc()
        else:
            print("Invalid choice! Please enter a number between 0 and 3")

if __name__ == "__main__":
    menu()