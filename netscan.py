#!/usr/bin/python3

import subprocess
import re
import requests
import os
from time import sleep
from urllib.parse import quote

NVD_API_KEY = os.getenv('NVD_API_KEY', '')  

def netdisc():
    print("\nRunning network discovery...")
    subprocess.run(["bash", "netdisc.sh"])
    print("Network discovery completed. Results saved in scan.txt")

def get_service_and_version(version_str):
    if not version_str or version_str.lower() == 'unknown':
        return None, None
    
    match = re.match(r'^([A-Za-z\-]+)[\s_]*([\d\.]+[a-zA-Z0-9\-\.]*)', version_str)
    if match:
        return match.group(1), match.group(2)
    
    return version_str, None

def check_cve_nvd(service, version):
    if not version:
        return []
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query = f"{service} {version}"
    
    params = {
        'keywordSearch': query,
        'resultsPerPage': 20
    }
    
    headers = {}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
    
    sleep(1)
    
    response = requests.get(url, params=params, headers=headers, timeout=15)
    data = response.json()
    
    cves = []
    for vuln in data.get('vulnerabilities', []):
        cve = vuln.get('cve', {})
        cve_id = cve.get('id', '')
        
        descriptions = [d['value'] for d in cve.get('descriptions', [])
                     if d.get('lang') == 'en']
        description = descriptions[0] if descriptions else 'No description'
        
        cves.append(f"{cve_id}: {description[:120]}...")
    
    return cves[:5]

def results(devices):
    if not devices:
        print("\nNo devices found.")
    else:
        print("\nDevices Found:\n")
        for ip, ports in devices.items():
            print(f" IP: {ip}")
            for port, service, version_info in ports:
                service_name, version = get_service_and_version(version_info)
                
                if not service_name:
                    service_name = service
                
                print(f"   -> {port}: {service_name} {f'(Version: {version})' if version else ''}")
                
                if version:
                    cves = check_cve_nvd(service_name, version)
                    if cves:
                        print("      CVEs Found:")
                        for cve in cves:
                            print(f"        - {cve}")
                    else:
                        print("      No known CVEs found.")
                else:
                    print("      Version not detected - cannot check CVEs")

def parse_nmap_results(nmap_output):
    devices = {}
    pattern = r"Nmap scan report for ([\d\.]+)\n.*?(\d+/tcp)\s+open\s+([\w\-]+)\s+(.+?)(?:\n\n|\Z)"
    
    matches = re.finditer(pattern, nmap_output, re.DOTALL)
    
    for match in matches:
        ip, port, service, version_info = match.groups()
        
        if ip not in devices:
            devices[ip] = []
        
        devices[ip].append((port, service, version_info))
    
    return devices

def netscan(network):
    print(f"\nScanning network: {network} (this may take several minutes)...\n")
    
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

def devscan(ip_address):
    print(f"\nScanning device: {ip_address}\n")
    
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