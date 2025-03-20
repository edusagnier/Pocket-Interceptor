#!/usr/bin/python3

import subprocess
import re
import requests

# Mostrar informacion de las tarhetas de red
def net_select():
    result = subprocess.run(["ip", "-4", "a"], capture_output=True, text=True)
    print("\nNetwork:\n")
    print(result.stdout)

# Escaneo de la red
def netscan(network):
    print(f"\nScanning the netwrok: {network}\n")
    comando = ["nmap", "-sV", "--min-parallelism", "10", "-p-", network]
    result = subprocess.run(comando, capture_output=True, text=True)
    
    pattern = r"Nmap scan report for ([\d\.]+).*?(\d+/tcp)\s+open\s+([\w\-]+)\s+([\w\.]+)"
    matches = re.findall(pattern, result.stdout, re.DOTALL)
    
    devices = {}
    for ip, port, service, version in matches:
        if ip not in devices:
            devices[ip] = []
        devices[ip].append((port, service, version))
    
    return devices
# Comparar respuestas con cves
def check_cve(service, version):
    query = f"{service} {version}"
    url = f"https://cve.circl.lu/api/search/{query}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return [cve["id"] for cve in data["data"]]
    else:
        print("Cant connect to the page!!!!")

if __name__ == "__main__":
    net_select()
    usernet = input("\nSelect a network (example: 192.168.1.0/24): ").strip()
    if not usernet:
        print("OOPS!! You didn't specify a network. Exiting...")
        exit()

    devices = netscan(usernet)
    if not devices:
        print("\nNo devices found.")
    else:
        print("\nDevices Found:\n")
        for ip, ports in devices.items():
            print(f" IP: {ip}")
            for port, service, version in ports:
                print(f"   ->{port}:{service} ({version})")
                cves = check_cve(service, version)
                if cves:
                    print("      CVEs Found:")
                    for cve in cves:
                        print(f"        - {cve}")
                else:
                    print("      No known CVEs found.")

