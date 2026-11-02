#!/usr/bin/python3

import subprocess
import re
import os
import sys
import ipaddress
from pathlib import Path
from time import sleep

try:
    import requests
except ImportError:
    requests = None

SCRIPT_DIRECTORY = Path(__file__).resolve().parent


class ScanError(Exception):
    """An expected execution failure that should be shown without a traceback."""


def validate_target(value, network=False):
    try:
        return str(ipaddress.IPv4Network(value, strict=False) if network
                   else ipaddress.IPv4Address(value))
    except (ValueError, ipaddress.AddressValueError):
        raise ScanError("Dirección IPv4 o prefijo de red no válido.") from None


def run_nmap(command, timeout):
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, check=True)
    except FileNotFoundError:
        raise ScanError("No se encuentra nmap. Comprueba que está instalado y disponible en PATH.") from None
    except PermissionError:
        raise ScanError("No hay permiso para ejecutar nmap.") from None
    except subprocess.TimeoutExpired:
        raise ScanError(f"Nmap superó el límite de {timeout // 60} minutos; el análisis no se completó.") from None
    except subprocess.CalledProcessError as error:
        # Do not let a terminal escape sequence in tool output control the menu.
        detail = ''.join(c for c in (error.stderr or '') if c.isprintable() or c == '\n')[:1000].strip()
        raise ScanError(f"Nmap falló con código {error.returncode}." +
                        (f" Detalle: {detail}" if detail else " Sin detalle adicional.")) from None
    except OSError:
        raise ScanError("El sistema no pudo iniciar nmap.") from None
    if not result.stdout.strip():
        raise ScanError("Nmap terminó sin salida; no se puede interpretar como una red sin dispositivos.")
    return parse_nmap_results(result.stdout)

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
        script = SCRIPT_DIRECTORY / "netdisc.sh"
        if not script.is_file():
            raise ScanError("No se encuentra el script netdisc.sh junto al escáner.")
        subprocess.run(["bash", str(script)], cwd=SCRIPT_DIRECTORY, check=True)
        print("El menú de descubrimiento ha terminado. Revisa los mensajes y resultados de esa opción.")
    # Manejo de errores si el script falla o no se encuentra
    except subprocess.CalledProcessError as e:
        raise ScanError(f"El descubrimiento terminó con código {e.returncode}; revisa el error anterior.") from None
    except FileNotFoundError:
        raise ScanError("No se encuentra bash para ejecutar el descubrimiento.") from None
    except PermissionError:
        raise ScanError("No hay permiso para ejecutar el script de descubrimiento.") from None

# Función para extraer la parte principal de la versión de un software
def get_clean_version(version):
    # Busca un patrón de versión principal (números y un punto)
    match = re.search(r'(\d+\.\d+)', version)
    # Devuelve la parte principal si la encuentra, de lo contrario, devuelve la versión original
    return match.group(1) if match else version

# Función principal para verificar CVEs de un servicio y su versión usando la API de NVD
def check_cve_nvd(service, version):
    if requests is None:
        print("[AVISO] Consulta CVE no disponible: falta el paquete Python requests.")
        return None
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
        response = getattr(e, 'response', None)
        status = getattr(response, 'status_code', None)
        if status == 429:
            reason = "límite de consultas alcanzado (HTTP 429)"
        elif status in (401, 403):
            reason = "acceso rechazado por NVD; revisa la configuración de acceso"
        elif status is not None:
            reason = f"respuesta HTTP {status}"
        else:
            reason = "fallo de conexión o tiempo de espera"
        print(f"[AVISO] No se pudo consultar NVD: {reason}.")
        return None
    except (ValueError, TypeError, KeyError, AttributeError):
        print("[AVISO] NVD devolvió una respuesta que no se pudo interpretar.")
        return None


# Define una función para mostrar los resultados del escaneo de dispositivos, incluyendo las CVEs encontradas
def results(devices, output_file=None):
    # Inicializa una lista para almacenar las líneas del output
    output = []

    if not devices:
        print("[AVISO] No se han podido extraer dispositivos de la salida. "
              "Esto no confirma que no existan: el parser actual tiene limitaciones.")
        return

    # Si se encontraron dispositivos, itera sobre ellos
    if devices:
        msg = "\nDevices Found:\n"
        print(msg)
        output.append(msg)

        for ip, ports in devices.items():
            ip_msg = f" IP: {ip}"
            print(ip_msg)
            output.append(ip_msg)

            # Itera sobre cada puerto, servicio y versión encontrados
            for port, service_raw, version in ports:
                # Obtiene el nombre del servicio mapeado
                service_mapped = SERVICE_MAPPING.get(service_raw.lower(), service_raw)
                port_msg = f"  -> {port}: {service_raw} ({service_mapped}, Version: {version})"
                print(port_msg)
                output.append(port_msg)

                # Busca CVEs para el servicio y la versión
                cves = check_cve_nvd(service_raw, version)
                if cves is None:
                    print("    Consulta CVE no completada; el estado de vulnerabilidades es desconocido.")
                elif cves:
                    cve_msg = "    CVEs Found:"
                    print(cve_msg)
                    output.append(cve_msg)
                    for cve in cves:
                        cve_item = f"      - {cve}"
                        print(cve_item)
                        output.append(cve_item)
                else:
                    no_cve = "    Sin coincidencias en esta consulta; no confirma ausencia de vulnerabilidades."
                    print(no_cve)
                    output.append(no_cve)

 
# Función para realizar un escaneo de red utilizando la herramienta Nmap.
def netscan(network):
    print(f"\nScanning network: {network} (this may take several minutes)...\n")
    network = validate_target(network, network=True)
    command = [
        "nmap", "-sV", "-T4", "--min-rate", "500",
        "--max-retries", "2", "-Pn", "-p1-10000", network
    ]
    return run_nmap(command, timeout=3600)


def devscan(ip_address):
    print(f"\nScanning device: {ip_address}\n")
    ip_address = validate_target(ip_address)
    command = [
        "nmap", "-sV", "-T4", "-Pn", "-p-",
        "--version-intensity", "7", ip_address
    ]
    return run_nmap(command, timeout=1800)


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
        elif choice in ("1", "2", "3"):
            try:
                if choice == "1":
                    network = input("\nEnter network to scan (e.g., 192.168.1.0/24): ").strip()
                    results(netscan(network))
                elif choice == "2":
                    address = input("\nEnter IP address to scan: ").strip()
                    results(devscan(address))
                else:
                    netdisc()
            except ScanError as error:
                print(f"[ERROR] {error}")
        else:
            print("Invalid choice! Please enter a number between 0 and 3")


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n[AVISO] Escaner cancelado.")
        sys.exit(130)
    except EOFError:
        print("\n[AVISO] Entrada cerrada; se termina el escaner.")
