#!/usr/bin/python3

import subprocess
import re
import requests
import os

# Mostrar información de las tarjetas de red
def netselect():
    result = subprocess.run(["ip", "-4", "a"], capture_output=True, text=True)
    print("\nAvailable Network Interfaces:\n")
    print(result.stdout)

    network = input("\nEnter the network to scan (e.g., 192.168.1.0/24): ").strip()
    if not network:
        print("Error: No network specified. Exiting...")
        exit()

    return network

# Limpiar la versión
def clean_version(version):
    # Extraer la parte numérica principal (por ejemplo, "9.7" de "OpenSSH 9.7p1")
    version_clean = re.match(r"(\d+\.\d+)", version)
    if version_clean:
        return version_clean.group(1)
    else:
        # Si no se puede extraer, usar solo la parte inicial (ejemplo: "OpenSSH")
        return version.split(" ")[0]

# Construir el CPE
def build_cpe(service, version):
    # Limpiar la versión
    version_clean = clean_version(version)
    
    # Construir el CPE con la versión limpia
    cpe = f"cpe:2.3:a:{service}:{service}:{version_clean}"
    return cpe

# Comparar respuestas con CVEs
def check_cve(service, version):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Intentar con la versión limpia
    cpe = build_cpe(service, version)
    params = {"cpeName": cpe}
    response = requests.get(base_url, params=params)
    
    if response.status_code == 200:
        data = response.json()
        if "vulnerabilities" in data and data["vulnerabilities"]:
            return [cve["cve"]["id"] for cve in data["vulnerabilities"]]
    
    print(f"⚠️ No valid CVEs found for {service} {version}. Trying with the service name only.")
    
    # Si no se encuentra con la versión completa, intentar con solo el servicio
    cpe_generic = f"cpe:2.3:a:{service}:{service}:*"
    params = {"cpeName": cpe_generic}
    response = requests.get(base_url, params=params)
    
    if response.status_code == 200:
        data = response.json()
        if "vulnerabilities" in data and data["vulnerabilities"]:
            return [cve["cve"]["id"] for cve in data["vulnerabilities"]]
    
    print(f"⚠️ No known CVEs found for {service} {version} or just {service}.")
    return []

# Printear Resultados
def results(devices):
    if not devices:
        print("\nNo devices found.")
    else:
        print("\nDevices Found:\n")
        for ip, ports in devices.items():
            print(f" IP: {ip}")
            for port, service, version in ports:
                print(f"   -> {port}: {service} (Version: {version})")
                # Si la version esta como "unknown", no hacemos la consulta de CVEs
                if version.lower() == "unknown":
                    print("⚠️ No valid version found. Skipping CVE check.")
                    print("      No known CVEs found.")
                else:
                    cves = check_cve(service, version)
                    if cves:
                        print("      CVEs Found:")
                        for cve in cves:
                            print(f"        - {cve}")
                    else:
                        print("      No known CVEs found.")

# Escaneo a la red
def netscan(network):
    print(f"\nScanning the entire network: {network}\n")
    command = ["nmap", "-sV", "--version-all", "-T4", "-p1-1000", network]
    result = subprocess.run(command, capture_output=True, text=True)
    
    # Expresión regular mejorada para capturar el puerto, servicio y la versión
    pattern = r"Nmap scan report for ([\d\.]+)\n.*?(\d+/tcp)\s+open\s+([\w\-]+)\s+([^\n]+)"
    matches = re.findall(pattern, result.stdout, re.DOTALL)
    
    devices = {}
    for ip, port, service, version in matches:
        # Limpiar la versión para que sea más precisa (si está disponible)
        version = version.strip() if version and version != 'unknown' else 'unknown'
        
        if ip not in devices:
            devices[ip] = []
        devices[ip].append((port, service, version))
    
    return devices

def devscan(ip_address):
    print(f"\nScanning device: {ip_address}\n")
    command = ["nmap", "-sV", "--version-all", "-T4", "-p1-1000", ip_address]
    result = subprocess.run(command, capture_output=True, text=True)
    
    # Expresión regular mejorada para capturar el puerto, servicio y la versión
    pattern = r"Nmap scan report for ([\d\.]+)\n.*?(\d+/tcp)\s+open\s+([\w\-]+)\s+([^\n]+)"
    matches = re.findall(pattern, result.stdout, re.DOTALL)
    
    device_info = []
    for _, port, service, version in matches:
        # Limpiar la versión para que sea más precisa (si está disponible)
        version = version.strip() if version and version != 'unknown' else 'unknown'
        device_info.append((port, service, version))
    
    return {ip_address: device_info}

# Escaneo con netdiscover
def netdisc():
    output_dir = "netscans"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "netdiscover_scan.txt")
    with open(output_file, "w") as f:
        subprocess.run(["netdiscover", "-r", "192.168.1.0/24"], stdout=f, text=True)
    print(f"Network scan saved in {output_file}")

# Menú principal
def menu():
    print("\nNetwork Scanner Menu:")
    print("1. Scan the entire network")
    print("2. Scan a single device")
    print("3. List the entire network and save it into a file")
    print("4. Exit")

    choice = input("\nEnter your choice (1/2/3/4): ").strip()
    
    if choice == "1":
        network = netselect()
        devices = netscan(network)
        results(devices)
    elif choice == "2":
        ip_address = input("\nEnter the IP address of the device to scan: ").strip()
        devices = devscan(ip_address)
        results(devices)
    elif choice == "3":
        netdisc()
    elif choice == "4":
        print("Exiting...")
        exit()
    else:
        print("Invalid choice! Please enter 1, 2, 3 or 4")
        menu()

if __name__ == "__main__":
    menu()