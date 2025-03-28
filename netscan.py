#!/usr/bin/python3

import subprocess
import re
import requests
import os
from time import sleep
from urllib.parse import quote

# Registra una key gratuita en: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.getenv('NVD_API_KEY', '')  

# Mapeo de nombres de servicios
SERVICE_MAPPING = {
    'ssh': 'OpenSSH',
    'http': 'Apache HTTP Server',
    'smtp': 'Postfix',
}

# Funcion que llama al script netdisc
def netdisc():
    try:
        print("\nRunning network discovery...")
        subprocess.run(["bash", "netdisc.sh"], check=True)
        print("Network discovery completed. Results saved in scan.txt")
    except subprocess.CalledProcessError as e:
        print(f"Error during network discovery: {e}")
    except FileNotFoundError:
        print("Error: netdisc.sh script not found")

def get_clean_version(version):
    match = re.search(r'(\d+\.\d+)', version)
    return match.group(1) if match else version

def check_cve_nvd(service, version):
    # Obtiene el nombre estandarizado del servicio
    product = SERVICE_MAPPING.get(service.lower(), service)
    version_clean = get_clean_version(version)
    
    try:
        # Configuración de la API NVD v2
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        query = f"{product} {version_clean}"
        
        params = {
            'keywordSearch': query,
            'resultsPerPage': 20
        }
        
        headers = {}
        if NVD_API_KEY:
            headers['apiKey'] = NVD_API_KEY
        
        # Pequeño delay para evitar rate limiting
        sleep(1)
        
        response = requests.get(url, params=params, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Obtiene la descripción 
            descriptions = [d['value'] for d in cve.get('descriptions', [])
                         if d.get('lang') == 'en']
            description = descriptions[0] if descriptions else 'No description'
            
            cves.append(f"{cve_id}: {description[:120]}...")
        
        return cves[:5]  # Limita a 5 resultados para mejor legibilidad
        
    except requests.exceptions.RequestException as e:
        print(f"NVD API request failed: {str(e)}")
        return []
    except Exception as e:
        print(f"Error processing NVD data: {str(e)}")
        return []

def results(devices, output_file=None):
    output = []
    
    if not devices:
        msg = "\nNo devices found."
        print(msg)
        output.append(msg)
    else:
        msg = "\nDevices Found:\n"
        print(msg)
        output.append(msg)
        
        for ip, ports in devices.items():
            ip_msg = f" IP: {ip}"
            print(ip_msg)
            output.append(ip_msg)
            
            for port, service, version in ports:
                port_msg = f"   -> {port}: {service} (Version: {version})"
                print(port_msg)
                output.append(port_msg)
                
                cves = check_cve_nvd(service, version)
                if cves:
                    cve_msg = "      CVEs Found:"
                    print(cve_msg)
                    output.append(cve_msg)
                    for cve in cves:
                        cve_item = f"        - {cve}"
                        print(cve_item)
                        output.append(cve_item)
                else:
                    no_cve = "      No known CVEs found."
                    print(no_cve)
                    output.append(no_cve)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(output))
        print(f"\nResults saved to {output_file}")

def netscan(network):
    print(f"\nScanning network: {network} (this may take several minutes)...\n")
    
    try:
        command = [
            "nmap", "-sV", "-T4", "--min-rate", "500", 
            "--max-retries", "2", "-Pn", "-p1-10000", network
        ]
        
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True,
            timeout=3600  
        )
        
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
            "nmap", "-sV", "-T4", "-Pn", "-p-", 
            "--version-intensity", "7", ip_address
        ]
        
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True,
            timeout=1800  
        )
        
        return parse_nmap_results(result.stdout)
        
    except subprocess.TimeoutExpired:
        print("Scan timed out after 30 minutes")
        return {ip_address: []}
    except Exception as e:
        print(f"Scan failed: {str(e)}")
        return {ip_address: []}

def parse_nmap_results(nmap_output):
    devices = {}
    pattern = r"Nmap scan report for ([\d\.]+)\n.*?(\d+/tcp)\s+open\s+([\w\-]+)\s+(.+?)(?:\n\n|\Z)"
    
    matches = re.finditer(pattern, nmap_output, re.DOTALL)
    
    for match in matches:
        ip, port, service, full_version = match.groups()
        version = extract_version(full_version)
        
        if ip not in devices:
            devices[ip] = []
        
        devices[ip].append((port, service, version))
    
    return devices

def extract_version(full_version):
    version_patterns = [
        r"(\d+\.\d+\.\d+[a-zA-Z0-9\-\.]*)",  # 1.2.3, 1.2.3a, 1.2.3-beta
        r"(\d+\.\d+[a-zA-Z0-9\-\.]*)",       # 1.2, 1.2a, 1.2-beta
        r"(\d+[a-zA-Z0-9\-\.]*)"             # 1, 1a, 1-beta
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, full_version)
        if match:
            return match.group(0)
    
    return "unknown"

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
            print("Invalid choice! Please enter a number between 1 and 4")

if __name__ == "__main__":

    menu()