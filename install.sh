#!/bin/bash

# Actualizar repositorios, suprimo la salida estandar para que quede mas limpio exceptuando errores
echo "Updating repositories..."
sudo apt update -y > /dev/null

# Instalar python3 y ipi
echo "Installing Python3 and pip..."
sudo apt install -y python3 python3-pip

# Instalar las librerias necesarias
echo "Installing Python dependencies with pip..."
pip3 install --upgrade pip
pip3 install subprocess

# Instalar nmap
echo "Installing Nmap..."
sudo apt install -y nmap > /dev/null

# Instalar BeefProject
echo "Installing BeefProject..."
git clone https://github.com/beefproject/beef.git
cd beef
sudo ./install

# Instalar Aircrack-ng
echo "Installing Aircrack-ng..."
sudo apt install -y aircrack-ng > /dev/null

clear

# Confirmar instalacion de las dependencias
echo "Installation completed. Verify dependencies:"
echo " - Python3: $(python3 --version)"
echo " - Pip: $(pip3 --version)"
echo " - Nmap: $(nmap --version | head -n 1)"
echo " - BeefProject: Verify installation in the 'beef/' directory"
echo " - Aircrack-ng: $(aircrack-ng --help | head -n 1)"
echo "All dependencies are installed."

echo "Configurando scripts..."
chmod +x netscan.py
