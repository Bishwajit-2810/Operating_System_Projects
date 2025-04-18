#!/bin/bash

set -e

echo "=== DHCP Server Setup for Ubuntu ==="


echo "[+] Installing isc-dhcp-server..."
sudo apt update && sudo apt install -y isc-dhcp-server


read -p "Enter the network interface to serve DHCP on (e.g., eth0, enp0s3): " IFACE


echo "[+] Configuring interface..."
sudo cp /etc/default/isc-dhcp-server /etc/default/isc-dhcp-server.bak
sudo bash -c "echo 'INTERFACESv4=\"$IFACE\"' > /etc/default/isc-dhcp-server"


echo "[+] Writing DHCP configuration..."
sudo cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.bak

cat <<EOF | sudo tee /etc/dhcp/dhcpd.conf > /dev/null
authoritative;

subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.100 192.168.1.200;
  option routers 192.168.1.1;
  option subnet-mask 255.255.255.0;
  option domain-name-servers 8.8.8.8, 8.8.4.4;
  default-lease-time 600;
  max-lease-time 7200;
}
EOF


echo "[+] Enabling and starting isc-dhcp-server..."
sudo systemctl enable isc-dhcp-server
sudo systemctl restart isc-dhcp-server

echo "=== DHCP Server setup completed! ==="
sudo systemctl status isc-dhcp-server

