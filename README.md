# ARP & DNS Spoofing and SSL Stripping with Scapy

## Overview
This project demonstrates how Address Resolution Protocol (ARP) manipulation and Domain Name System (DNS) redirection and SSL Stripping can be simulated.

The project consists of:
- **Tkinter-based GUI launcher**: A responsive control panel for managing attack parameters.
- **Asynchronous Python Engine**: A multi-threaded system implementing ARP poisoning, DNS interception, and packet injection.
- **Heuristic SSL Strip Proxy**: A transparent bridge that dynamically downgrades HTTPS connections to HTTP to capture credentials.

All components are designed for use inside two isolated virtual machines (Attacker and Victim) connected on the same virtual network.

---

## Workflow

1. The user launches the GUI interface and enters the **Gateway IP**, **Victim IP**, and **Domain Name** to target.
2. The system automatically configures the host environment by:
    - Enabling IPv4 kernel forwarding.
    - Setting up **iptables NAT redirection** to force Port 80 traffic into the proxy (Port 8080).
    - Injecting **iptables DROP rules** to block legitimate DNS responses from the gateway.
3. The core engine initiates three concurrent background threads:
    - **ARP Spooler**: Transmits spoofed ARP replies every 2 seconds to maintain the MITM position.
    - **DNS Sniffer**: Uses Scapy to intercept queries and inject forged `DNSRR` records.
    - **HTTP Proxy**: Launches the `SSLStripHandler` to negotiate protocol fallback.
4. When the victim attempts to access the targeted domain:
    - The DNS query is redirected to the attacker via Scapy injection.
    - The HTTP request is intercepted, stripped of SSL (if possible), and served in plaintext.
5. Any credentials entered into login forms are captured via `do_POST` interception and saved to `captured_data.txt`.

---

## Prerequisites

To run this framework inside an isolated environment, you need:

- **Python 3**
- **Tkinter** (for GUI)
- **Scapy** (for packet crafting and injection)
- **Requests & Urllib3** (for the heuristic proxy)
- **Two virtual machines** on the same NAT or Host-Only network.
- **Root/Sudo privileges** to modify the Linux networking stack.

Install required packages on the attacker VM:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk
pip3 install scapy
```
---

## Running the system

1. Open a terminal on the attacker VM.
2. Navigate to the project directory:
```bash
cd /path/to/project
```
3. Launch the GUI using:
```bash
sudo python3 launcher.py
```
4. Provide the identifiers ( victim machine(s) IP, and domain name(s) to spoof).
5. Select mode to run.
6. Click **Save & Run**.  
7. If prompted, enter your VM password (default for Kali Linux: kali)

---

