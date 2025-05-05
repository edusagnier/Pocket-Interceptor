#!/usr/bin/python3

import subprocess
import re
import requests
import os
from time import sleep

NVD_API_KEY = os.getenv('NVD_API_KEY', '')

def netdisc():
    try:
        print("\nRunning network discovery...")
        subprocess.run(["bash", "netdisc.sh"], check=True)
        print("Network discovery completed.")
    except subprocess.CalledProcessError as e:
        print(f"Error during network discovery: {e}")
    except FileNotFoundError:
        print("Error: netdisc.sh script not found")

def normalize_service_name(service):
    """Normaliza nombres de servicio para coincidir con la base de datos NVD"""
    service = service.lower().strip()
    
    # Mapeo de nombres comunes a sus equivalentes CPE estándar
    service_map = {
        'openssh': 'openssh',
        'apache httpd': 'http_server',
        'apache': 'http_server',
        'nginx': 'nginx',
        'microsoft iis': 'internet_information_server',
        'postgresql': 'postgresql',
        'mysql': 'mysql',
        'mariadb': 'mariadb',
        'vsftpd': 'vsftpd',
        'proftpd': 'proftpd',
        'samba': 'samba',
        'bind': 'bind'
    }
    
    return service_map.get(service, service.replace(' ', '_'))

def normalize_version(version):
    """Normaliza números de versión para coincidir con el formato CPE"""
    if not version or version.lower() == 'unknown':
        return None
        
    # Reemplaza formatos comunes
    version = re.sub(r'[vV]', '', version)
    version = re.sub(r'([0-9])[pP]([0-9])', r'\1.\2', version)  # 8.9p1 -> 8.9.1
    version = re.sub(r'([0-9])[rR]([0-9])', r'\1.\2', version)  # 1.2r3 -> 1.2.3
    version = re.sub(r'([0-9])[bB]([0-9])', r'\1.\2', version)  # 1.5b2 -> 1.5.2
    version = re.sub(r'[^0-9a-zA-Z.-]', '', version)  # Elimina caracteres especiales
    
    # Manejo de versiones con ceros finales
    version = re.sub(r'(\.0+)(?=[^0-9]|$)', r'\1', version)  # 2.4.0 -> 2.4
    return version

def extract_service_info(service_info):
    """Extrae nombre y versión del servicio de la cadena completa"""
    if not service_info or service_info.lower() == 'unknown':
        return None, None
    
    # Busca la versión primero
    version = None
    version_patterns = [
        r'(\d+\.\d+(?:\.\d+)?(?:[a-z]?\d*)(?:-[\w\d]+)?(?:~\w+)?)',  # 9.9p1, 2.4.62
        r'(\d+\.\d+\w+\d*)',                                          # 1.2b3
        r'(\d{4}-\d{2}-\d{2}(?:-\d+)?)',                              # Fechas
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, service_info)
        if match and any(c.isdigit() for c in match.group(1)):
            version = match.group(1)
            break
    
    # Extrae el nombre del servicio
    if version:
        version_pos = service_info.find(version)
        service_name = service_info[:version_pos].strip()
    else:
        service_name = service_info.strip()
    
    service_name = re.sub(r'[\W_]+$', '', service_name)
    return service_name or None, version

def check_cve_nvd(service, version):
    if not service or not version or version.lower() == 'unknown':
        return []

    try:
        service_norm = normalize_service_name(service)
        version_norm = normalize_version(version)
        
        if not service_norm or not version_norm:
            return []
        
        cpe = f"cpe:2.3:a:*:{service_norm}:{version_norm}:*:*:*:*:*:*:*"
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'cpeName': cpe, 'resultsPerPage': 20}
        headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}

        # Rate limiting de NVD
        sleep(6)  

        response = requests.get(url, params=params, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()

        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', '')
            
            descriptions = [d['value'] for d in cve.get('descriptions', [])
                         if d.get('lang') == 'en']
            description = descriptions[0] if descriptions else 'No description'
            
            metrics = cve.get('metrics', {})
            cvss_metric = next(iter(metrics.values()), [{}])[0]
            severity = cvss_metric.get('cvssData', {}).get('baseScore', 'N/A')
            
            cves.append(f"{cve_id} (CVSS: {severity}): {description[:100]}...")

        return cves[:10]  # Limitar a 10 resultados

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error checking CVEs: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return []
    except Exception as e:
        print(f"Error checking CVEs: {e}")
        return []

def parse_nmap_results(nmap_output):
    devices = {}
    current_ip = None
    
    for line in nmap_output.split('\n'):
        try:
            # Detección de nueva IP/host
            ip_match = re.match(r'Nmap scan report for ([\w\.-]+)', line.strip())
            if ip_match:
                current_ip = ip_match.group(1)
                devices[current_ip] = []
                continue
            
            if not current_ip:
                continue
            
            # Patrón para capturar puertos abiertos
            port_match = re.match(
                r'^(\d+)/(tcp|udp)\s+open\s+(\w+)(?:\s+([^\n]*))?$', 
                line.strip()
            )
            
            if port_match:
                port, proto, service, version_info = port_match.groups()
                version_info = version_info or ""
                
                service_name, version = extract_service_info(version_info)
                service_name = service_name or service
                
                devices[current_ip].append((
                    f"{port}/{proto}",
                    service_name,
                    version if version else "unknown"
                ))
        except Exception as e:
            print(f"Warning: Error parsing line - {str(e)}")
            continue
    
    return devices

def results(devices):
    if not devices:
        print("\nNo devices found.")
    else:
        print("\nDevices Found:\n")
        for ip, ports in devices.items():
            print(f"IP: {ip}")
            for port, service, version in ports:
                print(f"  {port}: {service}" + (f" (Version: {version})" if version != "unknown" else ""))
                
                if version != "unknown":
                    cves = check_cve_nvd(service, version)
                    if cves:
                        print("    CVEs Found:")
                        for cve in cves:
                            print(f"      - {cve}")
                    else:
                        print("    No known CVEs found for this version")

def netscan(network):
    print(f"\nScanning network: {network} (this may take several minutes)...\n")
    try:
        command = [
            "nmap", "-sV", "--version-intensity", "7", "-T4", 
            "--min-rate", "500", "--max-retries", "2", "-Pn", 
            "-p1-10000", "--open", network
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=3600)
        return parse_nmap_results(result.stdout)
    except subprocess.TimeoutExpired:
        print("Scan timed out after 1 hour")
        return {}
    except Exception as e:
        print(f"Scan failed: {str(e)}")
        return {}

def devscan(ip_address):
    print(f"\nScanning device: {ip_address}\n")
    try:
        command = [
            "nmap", "-sV", "--version-intensity", "7", "-T4", "-Pn", "-p-", 
            "--open", ip_address
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        return parse_nmap_results(result.stdout)
    except subprocess.TimeoutExpired:
        print("Scan timed out after 30 minutes")
        return {ip_address: []}
    except Exception as e:
        print(f"Scan failed: {str(e)}")
        return {ip_address: []}

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