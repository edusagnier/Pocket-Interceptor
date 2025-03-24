#!/bin/bash

menu() {
    echo -e "\nNetwork Discover Menu:"
    echo "1. List all possible addresses"
    echo "2. List an especific network"
    echo "3. Exit"

    read -p "Enter your choice (1/2/3/4): " choice

    case "$choice" in
        1)
            echo "Scanning the entire network..."
            sudo timeout 750 netdiscover -PN > data_collected/netmapping/scanall.txt
            ;;
        2)
            read -p "Enter the network (Ex: 192.168.1.0/24): " network
            sudo timeout 300 tnetdiscover -r 192.168.3.0/24 -PN > data_collected/netmapping/scan.txt
            ;;
        3)
            echo "Exiting..."
            exit
            ;;
        *)
            echo "Invalid choice! Please enter 1, 2, 3, or 4"
            menu
            ;;
    esac
}

menu
