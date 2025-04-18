#!/bin/bash

echo "=== DHCP Server Health Check ==="


echo -e "\n[+] Checking isc-dhcp-server status..."
sudo systemctl is-active --quiet isc-dhcp-server && echo "✅ DHCP server is running." || echo "❌ DHCP server is NOT running."


echo -e "\n[+] Validating /etc/dhcp/dhcpd.conf syntax..."
sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf && echo "✅ Config syntax OK." || echo "❌ Config syntax error!"


echo -e "\n[+] Checking if DHCP server is listening on ports 67/UDP..."
sudo netstat -anu | grep ':67 ' &> /dev/null && echo "✅ Port 67/UDP is open." || echo "❌ Port 67/UDP is not open."


echo -e "\n[+] Checking current leases..."
LEASES_FILE="/var/lib/dhcp/dhcpd.leases"
if [ -s "$LEASES_FILE" ]; then
    echo "✅ Active leases found:"
    grep lease "$LEASES_FILE" | grep -v "starts" | awk '{print $2}' | sort -u
else
    echo "ℹ️ No active leases yet. No clients may have requested an IP."
fi


read -p $'\n🔍 Want to watch real-time DHCP logs? [y/N]: ' WATCHLOG
if [[ "$WATCHLOG" =~ ^[Yy]$ ]]; then
    echo -e "\n[+] Showing live logs (press Ctrl+C to exit):"
    sudo journalctl -u isc-dhcp-server -f
else
    echo "✅ Health check completed."
fi

