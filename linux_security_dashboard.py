import tkinter as tk
from tkinter import ttk, messagebox, filedialog 
import hashlib
import os
from datetime import datetime
import psutil
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import seaborn as sns
import re
import random
import string
import pyperclip 
from cryptography.fernet import Fernet
import subprocess
import pyudev
import threading


class FileIntegrityMonitor:
    def __init__(self, master):
        self.master = master
        self.files_to_monitor = {}
        self.file_changes = []

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TButton", font=("Segoe UI", 10), padding=6)
        self.style.configure("TLabel", font=("Segoe UI", 11))
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"))

        ttk.Label(self.master, text="File Integrity Monitoring Tool", style="Header.TLabel").pack(pady=15)

        button_frame = ttk.Frame(self.master)
        button_frame.pack(pady=10)

        self.select_files_button = ttk.Button(button_frame, text="📂 Select Files to Monitor", command=self.select_files)
        self.select_files_button.grid(row=0, column=0, padx=10)

        self.monitor_button = ttk.Button(button_frame, text="🛡️ Start Monitoring", command=self.start_monitoring)
        self.monitor_button.grid(row=0, column=1, padx=10)

        self.status_label = ttk.Label(self.master, text="Status: Monitoring is OFF", foreground="red")
        self.status_label.pack(pady=10)

        self.selected_files_label = ttk.Label(self.master, text="No files selected.")
        self.selected_files_label.pack(pady=5)

        listbox_frame = ttk.Frame(self.master)
        listbox_frame.pack(pady=10)

        self.scrollbar = ttk.Scrollbar(listbox_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.files_listbox = tk.Listbox(listbox_frame, height=12, width=70, font=("Consolas", 10),
                                        yscrollcommand=self.scrollbar.set, bg="#f2f2f2", fg="#333")
        self.files_listbox.pack(side=tk.LEFT)
        self.scrollbar.config(command=self.files_listbox.yview)

    def calculate_checksum(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            messagebox.showerror("Error", f"Error reading file {file_path}: {e}")
            return None

    def select_files(self):
        file_paths = filedialog.askopenfilenames(title="Select Files to Monitor", filetypes=[("All Files", "*.*")])
        if file_paths:
            self.files_to_monitor.clear()
            self.file_changes.clear()

            self.selected_files_label.config(text=f"Selected {len(file_paths)} files.")
            self.files_listbox.delete(0, tk.END)

            for file_path in file_paths:
                checksum = self.calculate_checksum(file_path)
                if checksum:
                    self.files_to_monitor[file_path] = checksum
                    self.file_changes.append({'file': file_path, 'changes': []})
                    file_name = os.path.basename(file_path)
                    self.files_listbox.insert(tk.END, f"{file_name} - OK ✅")
            self.start_monitoring()

    def start_monitoring(self):
        if not self.files_to_monitor:
            messagebox.showwarning("No Files Selected", "Please select files to monitor.")
            return
        self.status_label.config(text="Status: Monitoring is ON", foreground="green")
        self.monitor_button.config(state=tk.DISABLED)
        self.check_files_integrity()

    def check_files_integrity(self):
        for file_path, original_checksum in list(self.files_to_monitor.items()):
            current_checksum = self.calculate_checksum(file_path)
            if current_checksum != original_checksum:
                modification_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.record_file_change(file_path, modification_time)
                self.update_files_listbox()
                messagebox.showwarning("Integrity Warning", f"File has been modified:\n{file_path}\nTime: {modification_time}")
                self.files_to_monitor[file_path] = current_checksum
        self.master.after(10000, self.check_files_integrity)

    def record_file_change(self, file_path, modification_time):
        for file_info in self.file_changes:
            if file_info['file'] == file_path:
                file_info['changes'].append(modification_time)
                break

    def update_files_listbox(self):
        self.files_listbox.delete(0, tk.END)
        for file_info in self.file_changes:
            file_name = os.path.basename(file_info['file'])
            if file_info['changes']:
                last_change = file_info['changes'][-1]
                self.files_listbox.insert(tk.END, f"{file_name} - Modified at {last_change} ⚠️")
            else:
                self.files_listbox.insert(tk.END, f"{file_name} - OK ✅")


class ResourceMonitorApp:
    def __init__(self, master):
        self.master = master

        sns.set_style("darkgrid")

        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 8))
        plt.subplots_adjust(hspace=0.5)

        self.x_data = []
        self.cpu_data = []
        self.ram_data = []

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.master)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.ani = FuncAnimation(self.fig, self.update, interval=1000, cache_frame_data=False)

    def update(self, frame):
        current_time = time.strftime("%H:%M:%S")
        self.x_data.append(current_time)

        cpu = psutil.cpu_percent(interval=0.1)
        self.cpu_data.append(cpu)
        self.ax1.clear()
        self.ax1.plot(self.x_data, self.cpu_data, label="CPU Usage", color="blue")
        self.ax1.set_title("CPU Usage (%)")
        self.ax1.set_xlabel("Time")
        self.ax1.set_ylabel("Usage (%)")
        self.ax1.legend(loc="upper left")
        self.ax1.grid(True)
        self.ax1.tick_params(axis='x', rotation=45)
        self.ax1.set_xticks(self.x_data[::5])  # Display every 5th timestamp
        self.ax1.text(0.95, 0.95, f"{cpu:.1f}%", transform=self.ax1.transAxes,
             fontsize=12, verticalalignment='top', horizontalalignment='right', color="blue")

        ram = psutil.virtual_memory().percent
        self.ram_data.append(ram)
        self.ax2.clear()
        self.ax2.plot(self.x_data, self.ram_data, label="RAM Usage", color="green")
        self.ax2.set_title("RAM Usage (%)")
        self.ax2.set_xlabel("Time")
        self.ax2.set_ylabel("Usage (%)")
        self.ax2.legend(loc="upper left")
        self.ax2.grid(True)
        self.ax2.tick_params(axis='x', rotation=45)
        self.ax2.set_xticks(self.x_data[::5])  
        self.ax2.text(0.95, 0.95, f"{ram:.1f}%", transform=self.ax2.transAxes,
             fontsize=12, verticalalignment='top', horizontalalignment='right', color="green")

        if len(self.x_data) > 30:
            self.x_data.pop(0)
            self.cpu_data.pop(0)
            self.ram_data.pop(0)

        self.canvas.draw()


class NetworkMonitorApp:
    def __init__(self, master):
        self.master = master

        self.create_network_monitor(master)

        self.net_data = {'sent': [], 'recv': []}
        self.last_net_io = psutil.net_io_counters()

        self.timestamps = []

        self.ani = FuncAnimation(self.ax_net.figure, self.update_network_info, interval=1000, save_count=50)
        self.ani._start() 

    def create_network_monitor(self, parent):
        panel = ttk.LabelFrame(parent, text="Network Activity", padding=10)
        panel.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.connection_tree = ttk.Treeview(panel, columns=('Proto', 'Local', 'Remote', 'Status', 'PID'), show='headings')
        
        self.connection_tree.heading('Proto', text='Protocol')
        self.connection_tree.heading('Local', text='Local Address')
        self.connection_tree.heading('Remote', text='Remote Address')
        self.connection_tree.heading('Status', text='Status')
        self.connection_tree.heading('PID', text='PID')
        
        self.connection_tree.column('Proto', width=60)
        self.connection_tree.column('Local', width=150)
        self.connection_tree.column('Remote', width=150)
        self.connection_tree.column('Status', width=80)
        self.connection_tree.column('PID', width=50)
        
        scrollbar = ttk.Scrollbar(panel, orient=tk.VERTICAL, command=self.connection_tree.yview)
        self.connection_tree.configure(yscroll=scrollbar.set)
        
        self.connection_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        fig, self.ax_net = plt.subplots(figsize=(6, 3), dpi=100)  # Bigger graph
        self.ax_net.set_title("Network Traffic", fontsize=12, fontweight='bold')
        self.ax_net.set_ylabel("KB/s", fontsize=10)
        self.ax_net.grid(True, linestyle='--', alpha=0.6)  # Light grid for readability
        
        self.canvas_net = FigureCanvasTkAgg(fig, master=panel)
        self.canvas_net.get_tk_widget().pack(fill=tk.BOTH, expand=True, pady=5)

    def update_network_info(self, frame=None):
        self.update_connection_info()
        self.update_network_traffic_graph()

    def update_connection_info(self):
        for item in self.connection_tree.get_children():
            self.connection_tree.delete(item)
        
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'LISTEN':
                    continue 
                
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                
                self.connection_tree.insert('', 'end', 
                                          values=(conn.type.name, 
                                                  laddr, 
                                                  raddr, 
                                                  conn.status, 
                                                  conn.pid or "N/A"))
        except (psutil.AccessDenied, PermissionError):
            self.connection_tree.insert('', 'end', values=("Access", "denied", "", "", ""))

    def update_network_traffic_graph(self):
        current_net_io = psutil.net_io_counters()
        elapsed = 1 
        
        sent_kb = (current_net_io.bytes_sent - self.last_net_io.bytes_sent) / 1024 / elapsed
        recv_kb = (current_net_io.bytes_recv - self.last_net_io.bytes_recv) / 1024 / elapsed

        self.net_data['sent'].append(sent_kb)
        self.net_data['recv'].append(recv_kb)
        self.timestamps.append(time.strftime("%H:%M:%S"))

        if len(self.net_data['sent']) > 30:
            self.net_data['sent'].pop(0)
            self.net_data['recv'].pop(0)
            self.timestamps.pop(0)

        self.ax_net.clear()
        self.ax_net.plot(self.timestamps, self.net_data['sent'], label="Sent", color='blue', linewidth=1.5)
        self.ax_net.plot(self.timestamps, self.net_data['recv'], label="Received", color='green', linewidth=1.5)

        self.ax_net.set_title(f"Network Traffic (Sent: {sent_kb:.1f} KB/s, Recv: {recv_kb:.1f} KB/s)", fontsize=12, fontweight='bold')
        self.ax_net.set_ylabel("KB/s", fontsize=10)
        self.ax_net.set_xlabel("Time", fontsize=10)
        self.ax_net.legend(loc='upper right', fontsize=9)
        self.ax_net.grid(True, linestyle='--', alpha=0.6)

        self.ax_net.set_xticks(range(0, len(self.timestamps), max(1, len(self.timestamps) // 10)))
        self.ax_net.set_xticklabels(self.timestamps[::max(1, len(self.timestamps) // 10)], rotation=30, ha='right')

        self.canvas_net.draw()

        self.last_net_io = current_net_io

class PasswordMonitorApp:
    def __init__(self, master):
        self.master = master

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=('Segoe UI', 10), padding=6)
        style.configure("TLabel", font=('Segoe UI', 11))

        ttk.Label(master, text="🔐 Password Strength Checker", font=('Segoe UI', 14, 'bold')).pack(pady=15)

        self.password_entry = ttk.Entry(master, show="*", width=30)
        self.password_entry.pack(pady=5)

        self.check_button = ttk.Button(master, text="Check Strength", command=self.check_password_strength)
        self.check_button.pack(pady=10)

        self.password_strength_label = ttk.Label(master, text="", font=('Segoe UI', 10))
        self.password_strength_label.pack(pady=5)

        ttk.Separator(master, orient='horizontal').pack(fill='x', pady=20)

        ttk.Label(master, text="🔁 Generate a Strong Password", font=('Segoe UI', 14, 'bold')).pack(pady=10)

        self.generated_password_label = ttk.Label(master, text="", font=('Segoe UI', 10), foreground="green")
        self.generated_password_label.pack(pady=5)

        self.generate_button = ttk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.pack(pady=10)

        self.copy_button = ttk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(pady=5)

    def check_password_strength(self):
        password = self.password_entry.get()
        strength = self.evaluate_password_strength(password)
        self.password_strength_label.config(text=f"Password Strength: {strength}")

    def evaluate_password_strength(self, password):
        length = len(password)
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

        if length < 6:
            return "❌ Weak"
        elif has_lower and has_upper and has_digit and has_special and length >= 12:
            return "✅ Very Strong"
        elif has_lower and has_upper and has_digit:
            return "✔️ Strong"
        elif has_lower or has_upper or has_digit:
            return "⚠️ Moderate"
        else:
            return "❌ Weak"

    def generate_password(self):
        password_length = 16
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(password_length))
        self.generated_password_label.config(text=f"Generated Password: {password}")
        self.generated_password = password

    def copy_to_clipboard(self):
        if hasattr(self, 'generated_password'):
            pyperclip.copy(self.generated_password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "Generate a password first!")


class SimpleEncryptionDecryptionTool:
    def __init__(self, master):
        self.master = master


        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=('Segoe UI', 10), padding=6)
        style.configure("TLabel", font=('Segoe UI', 11))

        self.encryption_frame = ttk.LabelFrame(master, text="🔐 Encryption", padding=15)
        self.encryption_frame.pack(padx=10, pady=10, fill='x')

        ttk.Label(self.encryption_frame, text="Encryption Key:").grid(row=0, column=0, sticky='w')
        self.key_entry = ttk.Entry(self.encryption_frame, width=50)
        self.key_entry.grid(row=0, column=1, pady=5)

        ttk.Button(self.encryption_frame, text="Generate Key", command=self.generate_key).grid(row=1, column=1, sticky='w')
        ttk.Button(self.encryption_frame, text="Copy Key", command=self.copy_key_to_clipboard).grid(row=1, column=1, sticky='e')

        ttk.Label(self.encryption_frame, text="Enter Message:").grid(row=2, column=0, sticky='w')
        self.message_entry = ttk.Entry(self.encryption_frame, width=50)
        self.message_entry.grid(row=2, column=1, pady=5)

        ttk.Button(self.encryption_frame, text="Encrypt", command=self.encrypt_message).grid(row=3, column=1, sticky='w', pady=5)

        self.encrypted_message_display = ttk.Label(self.encryption_frame, text="", foreground="green")
        self.encrypted_message_display.grid(row=4, column=0, columnspan=2, pady=5)

        ttk.Button(self.encryption_frame, text="Copy Encrypted", command=self.copy_encrypted_message).grid(row=5, column=1, sticky='e')

        self.decryption_frame = ttk.LabelFrame(master, text="🔓 Decryption", padding=15)
        self.decryption_frame.pack(padx=10, pady=10, fill='x')

        ttk.Label(self.decryption_frame, text="Encryption Key:").grid(row=0, column=0, sticky='w')
        self.decrypted_key_entry = ttk.Entry(self.decryption_frame, width=50)
        self.decrypted_key_entry.grid(row=0, column=1, pady=5)

        ttk.Label(self.decryption_frame, text="Encrypted Message:").grid(row=1, column=0, sticky='w')
        self.decrypted_message_entry = ttk.Entry(self.decryption_frame, width=50)
        self.decrypted_message_entry.grid(row=1, column=1, pady=5)

        ttk.Button(self.decryption_frame, text="Decrypt", command=self.decrypt_message).grid(row=2, column=1, sticky='w', pady=5)

        self.decrypted_message_result = ttk.Label(self.decryption_frame, text="", foreground="blue")
        self.decrypted_message_result.grid(row=3, column=0, columnspan=2, pady=5)

    def generate_key(self):
        key = Fernet.generate_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.decode())

    def encrypt_message(self):
        message = self.message_entry.get()
        key = self.key_entry.get().encode()

        if not message:
            messagebox.showwarning("Missing Message", "Please enter a message to encrypt.")
            return
        if not key:
            messagebox.showwarning("Missing Key", "Please generate or enter an encryption key.")
            return

        try:
            cipher = Fernet(key)
            encrypted = cipher.encrypt(message.encode()).decode()
            self.encrypted_message_display.config(text=f"{encrypted}")
        except Exception as e:
            self.encrypted_message_display.config(text="Invalid Key!")

    def decrypt_message(self):
        encrypted_message = self.decrypted_message_entry.get()
        key = self.decrypted_key_entry.get().encode()

        if not encrypted_message:
            messagebox.showwarning("Missing Encrypted Message", "Please enter the encrypted message.")
            return
        if not key:
            messagebox.showwarning("Missing Key", "Please enter the encryption key.")
            return

        try:
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_message.encode()).decode()
            self.decrypted_message_result.config(text=f"Decrypted: {decrypted}")
        except Exception:
            self.decrypted_message_result.config(text="Invalid key or message!")

    def copy_key_to_clipboard(self):
        key = self.key_entry.get()
        if key:
            pyperclip.copy(key)
            messagebox.showinfo("Copied", "Encryption key copied to clipboard!")

    def copy_encrypted_message(self):
        encrypted_message = self.encrypted_message_display.cget("text")
        if encrypted_message:
            pyperclip.copy(encrypted_message)
            messagebox.showinfo("Copied", "Encrypted message copied to clipboard!")


class FirewallRuleManager:
    def __init__(self, master):
        self.master = master

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=('Segoe UI', 10), padding=5)
        style.configure("TLabel", font=('Segoe UI', 11))

        self.add_rule_frame = ttk.LabelFrame(master, text="🚫 Add Firewall Rule", padding=15)
        self.add_rule_frame.pack(padx=10, pady=10, fill='x')

        ttk.Label(self.add_rule_frame, text="IP Address:").grid(row=0, column=0, sticky="w")
        self.ip_entry = ttk.Entry(self.add_rule_frame, width=40)
        self.ip_entry.grid(row=0, column=1, pady=5)

        ttk.Label(self.add_rule_frame, text="Port (optional):").grid(row=1, column=0, sticky="w")
        self.port_entry = ttk.Entry(self.add_rule_frame, width=40)
        self.port_entry.grid(row=1, column=1, pady=5)

        ttk.Button(self.add_rule_frame, text="Add Rule", command=self.add_rule).grid(row=2, column=1, sticky="w")

        self.remove_rule_frame = ttk.LabelFrame(master, text="✅ Remove Firewall Rule", padding=15)
        self.remove_rule_frame.pack(padx=10, pady=10, fill='x')

        ttk.Label(self.remove_rule_frame, text="IP to Unblock:").grid(row=0, column=0, sticky="w")
        self.remove_ip_entry = ttk.Entry(self.remove_rule_frame, width=40)
        self.remove_ip_entry.grid(row=0, column=1, pady=5)

        ttk.Button(self.remove_rule_frame, text="Remove Rule", command=self.remove_rule).grid(row=1, column=1, sticky="w")

        ttk.Button(master, text="List Current Rules", command=self.list_rules).pack(pady=5)
        self.rules_listbox = tk.Listbox(master, width=90, height=10, bg="#f0f0f0", font=('Courier', 10))
        self.rules_listbox.pack(pady=5)

        self.nslookup_frame = ttk.LabelFrame(master, text="🌐 NSLookup Tool", padding=15)
        self.nslookup_frame.pack(padx=10, pady=10, fill='x')

        ttk.Label(self.nslookup_frame, text="Domain (e.g., web.facebook.com):").grid(row=0, column=0, sticky="w")
        self.domain_entry = ttk.Entry(self.nslookup_frame, width=50)
        self.domain_entry.grid(row=0, column=1, pady=5)

        ttk.Button(self.nslookup_frame, text="Run NSLookup", command=self.run_nslookup).grid(row=1, column=1, sticky="w")
        ttk.Button(self.nslookup_frame, text="Block Domain", command=self.block_domain).grid(row=2, column=1, sticky="w", pady=5)

        self.nslookup_result_listbox = tk.Listbox(master, width=90, height=6, bg="#f0f0f0", font=('Courier', 10))
        self.nslookup_result_listbox.pack(pady=5)

    def add_rule(self):
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()

        if not ip:
            messagebox.showwarning("Missing IP", "Please enter an IP address.")
            return

        if port:
            command = f"sudo iptables -A INPUT -p tcp --dport {port} -s {ip} -j DROP"
            rule_text = f"Blocked {ip}:{port}"
        else:
            command = f"sudo iptables -A INPUT -s {ip} -j DROP"
            rule_text = f"Blocked {ip} (all ports)"

        try:
            subprocess.run(command, shell=True, check=True)
            self.rules_listbox.insert(tk.END, rule_text)
            messagebox.showinfo("Success", f"Firewall rule added for {ip}.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to add rule.\n{e}")

    def remove_rule(self):
        ip = self.remove_ip_entry.get().strip()

        if not ip:
            messagebox.showwarning("Missing IP", "Please enter an IP address.")
            return

        try:
            subprocess.run(f"sudo ipset del blocklist {ip}", shell=True, check=True)
            self.rules_listbox.insert(tk.END, f"Unblocked {ip}")
            messagebox.showinfo("Success", f"Removed {ip} from ipset blocklist.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to remove rule.\n{e}")

    def list_rules(self):
        try:
            result = subprocess.run("sudo ipset list blocklist", shell=True, text=True, check=True, capture_output=True)
            self.rules_listbox.delete(0, tk.END)
            for line in result.stdout.splitlines():
                self.rules_listbox.insert(tk.END, line)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to list rules.\n{e}")

    def run_nslookup(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Missing Domain", "Please enter a domain.")
            return

        command = f"nslookup {domain}"
        try:
            result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
            self.nslookup_result_listbox.delete(0, tk.END)
            for line in result.stdout.splitlines():
                self.nslookup_result_listbox.insert(tk.END, line)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"NSLookup failed.\n{e}")

    def block_domain(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Missing Domain", "Please enter a domain.")
            return

        command = f"nslookup {domain}"
        try:
            result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
            output = result.stdout

            self.nslookup_result_listbox.delete(0, tk.END)
            self.nslookup_result_listbox.insert(tk.END, f"Blocking IPs for: {domain}")

            blocked_ips = []
            for line in output.splitlines():
                if 'Address:' in line and not line.strip().startswith("Server:"):
                    ip = line.strip().split()[-1]
                    if self.is_valid_ipv4(ip) and ip not in blocked_ips:
                        try:
                            subprocess.run(f"sudo ipset add blocklist {ip}", shell=True, check=True)
                            self.rules_listbox.insert(tk.END, f"Blocked {ip} (from {domain})")
                            blocked_ips.append(ip)
                        except subprocess.CalledProcessError as e:
                            self.rules_listbox.insert(tk.END, f"❌ Failed to block {ip}: {e}")
            
            if not blocked_ips:
                self.nslookup_result_listbox.insert(tk.END, "No valid IPs found.")
            else:
                self.nslookup_result_listbox.insert(tk.END, f"Blocked IPs: {', '.join(blocked_ips)}")

        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to block domain.\n{e}")

    def is_valid_ipv4(self, ip):
        parts = ip.split('.')
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


class USBMonitorApp:
    def __init__(self, master):
        self.master = master

        self.create_ui()
        self.monitor_usb_devices()
        self.start_usb_event_listener()
    
    def create_ui(self):
        self.usb_frame = ttk.LabelFrame(self.master, text="🔌 Connected USB Devices")
        self.usb_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.usb_tree = ttk.Treeview(self.usb_frame, columns=("Bus", "Device", "ID", "Details"), show="headings", height=12)
        for col in ("Bus", "Device", "ID", "Details"):
            self.usb_tree.heading(col, text=col)
            self.usb_tree.column(col, width=150 if col != "Details" else 400)
        self.usb_tree.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(self.master)
        button_frame.pack(pady=5)
        
        self.refresh_button = ttk.Button(button_frame, text="🔄 Refresh USB Devices", command=self.monitor_usb_devices)
        self.refresh_button.grid(row=0, column=0, padx=5)
        
        self.details_button = ttk.Button(button_frame, text="🔍 Show Device Details", command=self.show_device_details)
        self.details_button.grid(row=0, column=1, padx=5)
        
        self.details_label = ttk.Label(self.master, text="Device details will appear here...", wraplength=750, justify="left")
        self.details_label.pack(pady=10)

    def monitor_usb_devices(self):
        """Retrieve and display currently connected USB devices using lsusb."""
        self.usb_tree.delete(*self.usb_tree.get_children())
        try:
            result = subprocess.run(["lsusb"], check=True, text=True, capture_output=True)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue  
                bus, device, usb_id = parts[1], parts[3][:-1], parts[5]
                details = " ".join(parts[6:])
                self.usb_tree.insert("", tk.END, values=(bus, device, usb_id, details))
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to fetch USB devices:\n{e}")

    def show_device_details(self):
        """Show detailed information about the selected device using udevadm info."""
        selected_item = self.usb_tree.selection()
        if not selected_item:
            self.details_label.config(text="⚠️ Please select a device to view details.")
            return

        device_info = self.usb_tree.item(selected_item, "values")
        bus, device = device_info[0], device_info[1]
        
        bus = bus.zfill(3)
        device = device.zfill(3)
        device_path = f"/dev/bus/usb/{bus}/{device}"

        try:
            result = subprocess.run(["udevadm", "info", "--query=all", "--name=" + device_path],
                                    check=True, text=True, capture_output=True)
            output = result.stdout.strip()
            self.details_label.config(text=(output[:500] + "...") if len(output) > 500 else output)
        except subprocess.CalledProcessError as e:
            self.details_label.config(text=f"❌ Error fetching details:\n{e}")

    def start_usb_event_listener(self):
        """Start a thread to monitor USB events."""
        threading.Thread(target=self.usb_event_listener, daemon=True).start()

    def usb_event_listener(self):
        """Real-time USB event monitoring using pyudev."""
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem='usb')
        for device in iter(monitor.poll, None):
            self.monitor_usb_devices()


class MainApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Linux Security Dashboard")
        self.master.geometry("945x940")
        
        self.tab_control = ttk.Notebook(self.master)
        
        self.create_tabs()

    def create_tabs(self):
        self.tab_fim = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_fim, text="File Integrity Monitor")
        self.fim_app = FileIntegrityMonitor(self.tab_fim)
        self.tab_control.pack(expand=1, fill="both")
        
        self.tab_rm = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_rm, text="Resource Monitor")
        self.rm_app = ResourceMonitorApp(self.tab_rm)

        self.tab_nm = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_nm, text="Network Monitor")
        self.nm_app = NetworkMonitorApp(self.tab_nm)

        self.tab_pm = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_pm, text="Password Checker")
        self.pm_app = PasswordMonitorApp(self.tab_pm)
        
        
        self.tab_encryption = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_encryption, text="Encryption/Decryption")
        self.ed_app = SimpleEncryptionDecryptionTool(self.tab_encryption)

        self.tab_encryption = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_encryption, text="Firewall Manager")
        self.fwIP_app = FirewallRuleManager(self.tab_encryption)
        
        self.tab_usb = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_usb, text="USB Monitor")
        self.usb_app = USBMonitorApp(self.tab_usb)

        
root = tk.Tk()
app = MainApp(root)
root.mainloop()
