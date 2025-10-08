# extract_evidence.py
from scapy.all import rdpcap, wrpcap
import json, sys

ALERT_FILE = "alerts.jsonl"
PCAP_FILE  = sys.argv[1] if len(sys.argv) > 1 else "Total_packets_log.pcap"
OUT_FILE   = "suspicious.pcap"

# load alerts
suspect_indexes = set()
with open(ALERT_FILE) as f:
    for line in f:
        try:
            alert = json.loads(line)
            ev = alert.get("evidence", None)
            if isinstance(ev, int):
                suspect_indexes.add(ev)
        except:
            continue

print("Will extract", len(suspect_indexes), "suspicious packets")

# read pcap and filter
pkts = rdpcap(PCAP_FILE)
suspect_pkts = [pkts[i] for i in suspect_indexes if i < len(pkts)]
wrpcap(OUT_FILE, suspect_pkts)
print("Wrote", OUT_FILE)
