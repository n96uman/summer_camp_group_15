#!/usr/bin/env python3
"""
Combine simple host IDS for IoT-Goat:
    - SYN/Stealth TCP scan detector
    - Fragment/overlap detector
    - ARP spoof/gratuitous ARP detector
    - DNS-tunneling style detector

Run with: sudo python3 ~/stealth_ids.py
"""

from scapy.all import sniff, IP, TCP, ARP, DNS, DNSQR
from collections import defaultdict
import time
import sys
import signal

# ---------- Config ----------
SYN_THRESHOLD = 20
SYN_WINDOW = 10

FRAG_WINDOW = 10
FRAG_THRESHOLD = 30

GRAT_THRESHOLD = 5
GRAT_WINDOW = 10

DNS_WINDOW = 60
UNIQUE_SUBDOMAIN_THRESHOLD = 50
LONG_LABEL_LEN = 50

# ---------- Data stores ----------
syn_events = defaultdict(list)
frag_records = defaultdict(list)   # key=(src,dst,id) -> list of (offset, length, ts)
ip_mac = {}
gratarp_count = defaultdict(list)
domain_subs = defaultdict(lambda: {"subs": set(), "times": []})

# ---------- Helpers ----------
def cleanup_syn():
    now = time.time()
    for ip in list(syn_events.keys()):
        syn_events[ip] = [t for t in syn_events[ip] if now - t <= SYN_WINDOW]
        if not syn_events[ip]:
            del syn_events[ip]

def flag_name(tcp):
    f = tcp.flags
    if f == 0:
        return "NULL"
    if (f & 0x02) and not (f & 0x10):
        return "SYN"
    if f == 0x01:
        return "FIN"
    if (f & 0x29) == 0x29:
        return "XMAS"
    return str(f)

def check_overlaps(key, offset, length_bytes):
    recs = frag_records[key]
    new_start = offset * 8
    new_end = new_start + length_bytes
    for off, l, _ in recs:
        exist_start = off * 8
        exist_end = exist_start + l
        if not (new_end <= exist_start or new_start >= exist_end):
            return True, (exist_start, exist_end)
    return False, None

def cleanup_frag():
    now = time.time()
    for k in list(frag_records.keys()):
        frag_records[k] = [(o,l,t) for (o,l,t) in frag_records[k] if now - t <= FRAG_WINDOW]
        if not frag_records[k]:
            del frag_records[k]

# ---------- Packet callback ----------
def pkt_cb(pkt):
    now = time.time()
    if IP in pkt:
        if not ( pkt[IP].src == "IOT_goat_IP" or pkt[IP].dst=="IOT_goat_IP")
    # --- TCP stealth detection ---
    if IP in pkt and TCP in pkt:
        ip = pkt[IP].src
        tcp = pkt[TCP]
        name = flag_name(tcp)
        if name == "SYN" and not (tcp.flags & 0x10):
            syn_events[ip].append(now)
            cleanup_syn()
            count = len(syn_events[ip])
            if count >= SYN_THRESHOLD:
                print(f"[ALERT] Potential SYN scan from {ip} — {count} SYNs in last {SYN_WINDOW}s")
        elif name in ("FIN", "XMAS", "NULL"):
            print(f"[ALERT] Potential stealth scan ({name}) from {ip} -> {pkt[IP].dst}:{tcp.dport}")

    # --- Fragment / overlap detection ---
    if IP in pkt:
        ip = pkt[IP]
        if (ip.flags & 0x1) or ip.frag != 0:
            key = (ip.src, ip.dst, ip.id)
            # length of payload in bytes
            payload_len = len(bytes(ip.payload))
            is_overlap, existing = check_overlaps(key, ip.frag, payload_len)
            frag_records[key].append((ip.frag, payload_len, now))
            cleanup_frag()
            total_frags = sum(len(v) for v in frag_records.values())
            if is_overlap:
                print(f"[ALERT] Overlapping fragment from {ip.src} to {ip.dst} id={ip.id}. Overlap with {existing}")
            elif total_frags > FRAG_THRESHOLD:
                print(f"[ALERT] High fragment volume: {total_frags} frags in last {FRAG_WINDOW}s")
    # --- ARP spoof / gratuitous ARP ---
    if ARP in pkt and pkt[ARP].op in (1,2):
        ip_src = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if pkt[ARP].psrc == pkt[ARP].pdst:
            gratarp_count[ip_src].append(now)
            gratarp_count[ip_src] = [t for t in gratarp_count[ip_src] if now - t <= GRAT_WINDOW]
            if len(gratarp_count[ip_src]) >= GRAT_THRESHOLD:
                print(f"[ALERT] Rapid gratuitous ARP for {ip_src} ({len(gratarp_count[ip_src])} in {GRAT_WINDOW}s)")
        if ip_src in ip_mac:
            prev_mac, _ = ip_mac[ip_src]
            if prev_mac != mac:
                print(f"[ALERT] IP->MAC change for {ip_src}: {prev_mac} -> {mac} (possible spoofing)")
        ip_mac[ip_src] = (mac, now)

    # --- DNS tunneling heuristics ---
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qdcount > 0:
        dns = pkt[DNS]
        qname = dns.qd.qname.decode(errors='ignore').rstrip('.')
        parts = qname.split('.')
        if len(parts) >= 2:
            root = '.'.join(parts[-2:])
            sub = '.'.join(parts[:-2]) if len(parts) > 2 else ''
            # long label check
            for lab in parts:
                if len(lab) >= LONG_LABEL_LEN:
                    src = pkt[IP].src if IP in pkt else "unknown"
                    print(f"[ALERT] Long DNS label ({len(lab)} chars) in query {qname} from {src}")
            # many unique subdomains
            ds = domain_subs[root]
            ds["subs"].add(sub)
            ds["times"].append(now)
            ds["times"] = [t for t in ds["times"] if now - t <= DNS_WINDOW]
            if len(ds["subs"]) >= UNIQUE_SUBDOMAIN_THRESHOLD:
                print(f"[ALERT] {len(ds['subs'])} unique subdomains for {root} in {DNS_WINDOW}s (possible DNS tunneling)")
                ds["subs"].clear()

# ---------- Runner ----------
def signal_handler(sig, frame):
    print("\nStopping IDS...")
    sys.exit(0)

def main():
    print("Starting combined host IDS (press Ctrl+C to stop). Running as root may be required.")
    signal.signal(signal.SIGINT, signal_handler)
    # sniff everything; change filter if desired, e.g. "udp port 53 or arp"
    sniff(prn=pkt_cb, store=0)

if __name__ == '__main__':
    main()