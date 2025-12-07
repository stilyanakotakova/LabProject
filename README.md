# ARP & DNS Spoofing and SSL Stripping with Scapy

## Overview
This project demonstrates how Address Resolution Protocol (ARP) manipulation and Domain Name System (DNS) redirection can be simulated. It also lays the groundwork for adding SSL Stripping during the final stage of the project.

The project consists of:
- A **Tkinter-based GUI launcher**  
- A **Python engine** that implements ARP routing manipulation and DNS response interception  
- A **local webserver** that hosts a controlled spoofed webpage 

All components are designed for use inside two isolated virtual machines connected on the same virtual network.

---

## Workflow

1. The user launches the GUI interface.
2. The user enters:
   - **Gateway IP**  
   - **Attacker IP**
   - **Victim IP** 
   - **Domain name** to demonstrate redirection  
3. The system automatically generates:
   - A DNS mapping file (`dnsSpoofed.txt`)  
   - A spoofed webpage stored in `spoof_site/index.html`  
4. A lightweight Python HTTP server starts on **port 80**, hosting the spoofed webpage.  
5. The core engine begins:
   - ARP announcements (used to demonstrate routing influence)  
   - IP forwarding behavior  
   - DNS query interception and redirection  
6. When the victim VM tries to access the chosen domain, it is shown the demonstration webpage hosted by the attacker VM.

This helps visualize how network misdirection works at a conceptual, protocol-level perspective.

---

## Prerequisites

To run this attack inside an isolated environment, you need:

- **Python 3**
- **Tkinter** (for GUI)
- **Scapy** (for packet crafting and protocol demonstration)
- **Two virtual machines** on the same NAT or Host-Only network (Attacker VM and Victim VM)
- Sufficient privileges inside the isolated VM environment to modify routing behavior

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
python3 launcher.py
```
4. Provide the identifiers (gateway IP, attacker IP, victim machine IP, and domain name to spoof).  
5. Click **Save & Run**.  
6. When prompted, enter your VM password (default for Kali Linux: kali)
7. After authentication, the system will:
   - Generate the DNS mapping file  
   - Create the spoofed webpage  
   - Start the local webserver  
   - Begin the simulation engine  

The victim machine will observe redirected traffic when visiting the chosen domain.
---
