#!/bin/bash

# Check if the script is run with sudo
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[1;31mThis script must be run as root (use sudo).\033[0m"
    exit 1
fi

# Function to display the welcome message and menu options
display_menu() {
    clear
    echo -e "\033[1;34m-----------------------------------------------\033[0m"
    echo -e "\033[1;32m       TinyProxy with Website Blocking       \033[0m"
    echo -e "\033[1;34m-----------------------------------------------\033[0m"
    echo -e "\033[1;33m1) Install and Configure TinyProxy\033[0m"
    echo -e "\033[1;33m2) Block a Website\033[0m"
    echo -e "\033[1;33m3) Unblock a Website\033[0m"
    echo -e "\033[1;33m4) View Blocked Websites\033[0m"
    echo -e "\033[1;33m5) Restart TinyProxy\033[0m"
    echo -e "\033[1;31m6) Exit\033[0m"
    echo -e "\033[1;34m-----------------------------------------------\033[0m"
    echo -n -e "\033[1;36mPlease choose an option [1-6]: \033[0m"
}

# Function to install and configure TinyProxy and UFW
install_and_configure() {
    echo -e "\033[1;32mUpdating system and installing TinyProxy and UFW...\033[0m"
    apt update && apt upgrade -y
    apt install -y tinyproxy ufw dnsutils 

    # Set up UFW to allow necessary traffic
    echo -e "\033[1;32mConfiguring UFW firewall...\033[0m"

    # Allow SSH (port 22) and HTTP (port 80) for basic web access
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp

    # Allow TinyProxy port (8888 by default)
    ufw allow 8888/tcp

    # Enable UFW
    ufw --force enable

    # Backup the original TinyProxy configuration file
    cp /etc/tinyproxy/tinyproxy.conf /etc/tinyproxy/tinyproxy.conf.bak

    # Define subnet for access (adjust as needed)
    SUBNET="192.168.1.0/24"

    # Set up the basic TinyProxy configuration (listening on port 8888)
    sed -i 's/^#Port 8888/Port 8888/' /etc/tinyproxy/tinyproxy.conf
    sed -i "s/^#Allow 127.0.0.1/Allow $SUBNET/" /etc/tinyproxy/tinyproxy.conf

    # Enable and start TinyProxy using systemctl
    systemctl enable tinyproxy
    systemctl start tinyproxy

    echo -e "\033[1;32mTinyProxy and UFW have been installed and configured successfully!\033[0m"
}

# Function to block a website by resolving domain to IP and modifying UFW rules
block_website() {
    echo -n -e "\033[1;36mEnter the website to block (e.g., example.com): \033[0m"
    read website

    # Resolve the domain to an IP address
    ip_address=$(dig +short $website)

    # Check if we received an IP address
    if [ -z "$ip_address" ]; then
        echo -e "\033[1;31mFailed to resolve the domain. Please check the website name.\033[0m"
        return
    fi

    # Use UFW to block the website by rejecting outgoing traffic (HTTP and HTTPS) based on IP
    ufw deny out to $ip_address port 80
    ufw deny out to $ip_address port 443

    # Block ping (ICMP) traffic to the website IP
    ufw deny out to $ip_address proto icmp

    echo -e "\033[1;32m$website ($ip_address) has been blocked (web traffic and ping).\033[0m"
}

# Function to unblock a website by removing the UFW rules
unblock_website() {
    echo -n -e "\033[1;36mEnter the website to unblock (e.g., example.com): \033[0m"
    read website

    # Resolve the domain to an IP address
    ip_address=$(dig +short $website)

    # Check if we received an IP address
    if [ -z "$ip_address" ]; then
        echo -e "\033[1;31mFailed to resolve the domain. Please check the website name.\033[0m"
        return
    fi

    # Remove UFW rules to unblock the website
    ufw delete deny out to $ip_address port 80
    ufw delete deny out to $ip_address port 443

    # Remove ICMP block
    ufw delete deny out to $ip_address proto icmp

    echo -e "\033[1;32m$website ($ip_address) has been unblocked.\033[0m"
}

# Function to view blocked websites
view_blocked_websites() {
    echo -e "\033[1;33mCurrently blocked websites (UFW rules for outgoing traffic):\033[0m"
    ufw status numbered | grep "DENY OUT"
}

# Function to restart TinyProxy service
restart_tinyproxy() {
    echo -e "\033[1;32mRestarting TinyProxy service...\033[0m"
    systemctl restart tinyproxy
    echo -e "\033[1;32mTinyProxy service restarted.\033[0m"
}

# Main program loop
while true; do
    display_menu
    read -r option

    case $option in
        1)
            install_and_configure
            ;;
        2)
            block_website
            ;;
        3)
            unblock_website
            ;;
        4)
            view_blocked_websites
            ;;
        5)
            restart_tinyproxy
            ;;
        6)
            echo -e "\033[1;31mExiting... Goodbye!\033[0m"
            exit 0
            ;;
        *)
            echo -e "\033[1;31mInvalid option. Please choose a valid option [1-6].\033[0m"
            ;;
    esac

    # Pause before showing the menu again
    echo -n -e "\033[1;36mPress Enter to return to the menu...\033[0m"
    read -r
done
