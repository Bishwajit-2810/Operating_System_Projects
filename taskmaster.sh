#!/bin/bash

# Function to list top processes
list_processes() {
    echo "Process ID | User | CPU (%) | Memory (%) | Command"
    echo "-----------------------------------------------"
    ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -n 15
}

# Function to start a new process
start_process() {
    read -p "Enter the command to start a new process: " cmd
    $cmd &   # Start the command in the background
    pid=$!   # Capture the process ID of the last background command
    echo "Started process '$cmd' with PID: $pid"
}

# Function to stop a process
stop_process() {
    read -p "Enter PID to stop: " pid
    kill -STOP $pid && echo "Process $pid stopped"
}

# Function to resume a process
resume_process() {
    read -p "Enter PID to resume: " pid
    kill -CONT $pid && echo "Process $pid resumed"
}

# Function to kill a process
kill_process() {
    read -p "Enter PID to kill: " pid
    kill -9 $pid && echo "Process $pid killed"
}

# Function to monitor a process
monitor_process() {
    read -p "Enter PID to monitor: " pid
    top -p $pid
}

# Function to show process priority
show_priority() {
    read -p "Enter PID to check priority: " pid
    ps -o pid,ni,comm -p $pid
}

# Function to check internet speed
check_internet_speed() {
    echo "Checking internet speed..."
    speedtest-cli
}

# Function to check network connections
check_network_connections() {
    echo "Active Network Connections:"
    ss -tuln
}

# Function to change process priority
change_process_priority() {
    read -p "Enter the PID to change priority: " pid
    read -p "Enter the nice value (-20 to 19): " nice_value
    renice $nice_value -p $pid && echo "Priority for PID $pid changed to $nice_value"
}

# Function to view CPU and memory usage
view_cpu_memory_usage() {
    top -b -n 1 | head -n 10
}

# Function to set CPU affinity for a process
set_cpu_affinity() {
    read -p "Enter the PID to set CPU affinity: " pid
    read -p "Enter CPU cores to assign (e.g., 0,1): " cores
    taskset -cp $cores $pid && echo "Set CPU affinity for PID $pid to cores $cores"
}

# Function to schedule a task
schedule_task() {
    echo "1. Schedule one-time task (at)"
    echo "2. Schedule recurring task (cron)"
    read -p "Choose an option: " opt
    if [ "$opt" -eq 1 ]; then
        read -p "Enter time for task (e.g., now + 5 minutes): " time
        read -p "Enter command to execute: " cmd
        echo "$cmd" | at $time && echo "Scheduled task for $time"
    elif [ "$opt" -eq 2 ]; then
        read -p "Enter cron schedule (e.g., '0 5 * * *'): " schedule
        read -p "Enter command to execute: " cmd
        (crontab -l; echo "$schedule $cmd") | crontab -
        echo "Cron job added."
    else
        echo "Invalid option."
    fi
}

# Function to display disk usage
display_disk_usage() {
    df -h | grep "^/dev"
}

# Function to monitor system uptime
monitor_system_uptime() {
    uptime
}

# Function to set process resource limits
set_process_resource_limits() {
    read -p "Enter the resource limit (e.g., max file size in KB): " limit
    ulimit -f $limit && echo "Set file size limit to $limit KB"
}

# Function to view active users
view_active_users() {
    who
}

# Function to log process events
log_process_events() {
    read -p "Enter PID to log: " pid
    read -p "Enter log file name (e.g., process_log.txt): " logfile
    echo "Logging CPU and memory usage for PID $pid to $logfile (Press Ctrl+C to stop)"
    while true; do
        ps -p $pid -o %cpu,%mem,cmd >> $logfile
        sleep 5
    done
}

# Function to generate a system report
generate_system_report() {
    report_file="system_report_$(date +'%Y%m%d_%H%M%S').txt"
    echo "Generating system report to $report_file"
    echo "System Information:" > $report_file
    uname -a >> $report_file
    echo -e "\nMemory Usage:" >> $report_file
    free -h >> $report_file
    echo -e "\nDisk Usage:" >> $report_file
    df -h >> $report_file
    echo -e "\nTop Processes:" >> $report_file
    ps aux --sort=-%mem | head -n 10 >> $report_file
    echo -e "\nNetwork Connections:" >> $report_file
    ss -tuln >> $report_file
    echo "System report generated."
}

# Function to install DNS server (bind9)
install_dns_server() {
    echo "Installing DNS server..."
    sudo apt-get install bind9 -y && echo "DNS server installed."
}

# Function to configure DNS zones
# Function to configure DNS zones
configure_dns_zones() {
    echo "Configuring DNS zones..."
    
    # Prompt user for domain and IP address
    read -p "Enter domain name (e.g., example.com): " domain
    read -p "Enter IP address for $domain: " ip_address
    read -p "Enter reverse zone (e.g., 1.168.192 for 192.168.1.x subnet): " reverse_zone

    # Define paths for forward and reverse zone files
    forward_zone_file="/etc/bind/db.$domain"
    reverse_zone_file="/etc/bind/db.$reverse_zone"

    # Configure forward zone
    echo "Creating forward zone file..."
    sudo bash -c "cat > $forward_zone_file" <<EOL
\$TTL 604800
@       IN      SOA     $domain. root.$domain. (
                        2         ; Serial
                        604800    ; Refresh
                        86400     ; Retry
                        2419200   ; Expire
                        604800 )  ; Negative Cache TTL
;
@       IN      NS      ns.$domain.
ns      IN      A       $ip_address
@       IN      A       $ip_address
www     IN      A       $ip_address
EOL

    # Configure reverse zone
    echo "Creating reverse zone file..."
    sudo bash -c "cat > $reverse_zone_file" <<EOL
\$TTL 604800
@       IN      SOA     $domain. root.$domain. (
                        2         ; Serial
                        604800    ; Refresh
                        86400     ; Retry
                        2419200   ; Expire
                        604800 )  ; Negative Cache TTL
;
@       IN      NS      ns.$domain.
$(echo $ip_address | awk -F. '{print $4}') IN PTR $domain.
EOL

    # Update named.conf.local with the new zone configurations
    echo "Updating named.conf.local with zone configurations..."
    sudo bash -c "cat >> /etc/bind/named.conf.local" <<EOL

zone "$domain" {
    type master;
    file "$forward_zone_file";
};

zone "$reverse_zone.in-addr.arpa" {
    type master;
    file "$reverse_zone_file";
};
EOL

    echo "DNS zones configured for $domain with IP $ip_address."
}


# Function to start DNS server
start_dns_server() {
    sudo systemctl start bind9 && echo "DNS server started."
}

# Function to stop DNS server
stop_dns_server() {
    sudo systemctl stop bind9 && echo "DNS server stopped."
}

# Function to check DNS server status
check_dns_status() {
    sudo systemctl status bind9
}

# Main interactive menu
while true; do
    echo "====== TaskMaster Menu ======"
    echo "1. List Top Processes"
    echo "2. Start a Process"
    echo "3. Stop a Process"
    echo "4. Resume a Process"
    echo "5. Kill a Process"
    echo "6. Monitor a Process"
    echo "7. Show Process Priority"
    echo "8. Check Internet Speed"
    echo "9. Check Network Connections"
    echo "10. Change Process Priority"
    echo "11. View CPU and Memory Usage"
    echo "12. Set CPU Affinity for a Process"
    echo "13. Schedule a Task (at/cron jobs)"
    echo "14. Display Disk Usage"
    echo "15. Monitor System Uptime"
    echo "16. Set Process Resource Limits (ulimit)"
    echo "17. View Active Users"
    echo "18. Log Process Events"
    echo "19. Generate System Report"
    echo "20. Install DNS Server"
    echo "21. Configure DNS Zones"
    echo "22. Start DNS Server"
    echo "23. Stop DNS Server"
    echo "24. Check DNS Server Status"
    echo "25. Exit"
    echo "============================="
    read -p "Choose an option: " choice

    case $choice in
        1) list_processes ;;
        2) start_process ;;
        3) stop_process ;;
        4) resume_process ;;
        5) kill_process ;;
        6) monitor_process ;;
        7) show_priority ;;
        8) check_internet_speed ;;
        9) check_network_connections ;;
        10) change_process_priority ;;
        11) view_cpu_memory_usage ;;
        12) set_cpu_affinity ;;
        13) schedule_task ;;
        14) display_disk_usage ;;
        15) monitor_system_uptime ;;
        16) set_process_resource_limits ;;
        17) view_active_users ;;
        18) log_process_events ;;
        19) generate_system_report ;;
        20) install_dns_server ;;
        21) configure_dns_zones ;;
        22) start_dns_server ;;
        23) stop_dns_server ;;
        24) check_dns_status ;;
        25) echo "Exiting TaskMaster"; break ;;
        *) echo "Invalid option. Try again." ;;
    esac
    echo ""
done

