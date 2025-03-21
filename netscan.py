#!/usr/bin/python3

import subprocess
import re
import requests
import sys

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

# Comparar respuestas con CVEs
def check_cve(service, version):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query = f"{service} {version}"
    params = {
        "keywordSearch": query,
    }
    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        data = response.json()
        if "vulnerabilities" in data:
            return [cve["cve"]["id"] for cve in data["vulnerabilities"]]
    print("Can't connect to the NVD CVE database!")
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
    command = ["nmap", "-sV", "--min-parallelism", "10", "-p-", network]
    result = subprocess.run(command, capture_output=True, text=True)
    pattern = r"Nmap scan report for ([\d\.]+)\n.*?(\d+/tcp)\s+open\s+([\w\-]+)\s+([\w\.]+)"
    matches = re.findall(pattern, result.stdout, re.DOTALL)
    devices = {}
    for ip, port, service, version in matches:
        if ip not in devices:
            devices[ip] = []
        devices[ip].append((port, service, version))
    
    return devices

# Escaneo a un único dispositivo
def devscan(ip_address):
    print(f"\nScanning device: {ip_address}\n")
    command = ["nmap", "-sV", "--min-parallelism", "10", "-p-", ip_address]
    result = subprocess.run(command, capture_output=True, text=True)
    pattern = r"Nmap scan report for ([\d\.]+)\n.*?(\d+/tcp)\s+open\s+([\w\-]+)\s+([\w\.]+)"
    matches = re.findall(pattern, result.stdout, re.DOTALL)
    device_info = []
    for _, port, service, version in matches:
        device_info.append((port, service, version))
    
    return {ip_address: device_info}


def netdisc():
    subprocess.run(["bash", "netdisc.sh"])

def menu():
    print("\nNetwork Scanner Menu:")
    print("1. Scan the entire network")
    print("2. Scan a single device")
    print("3. List the entire network and save it into a file")
    print("4. Exit")

    choice = input("\nEnter your choice (1/2/3): ").strip()
    
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
