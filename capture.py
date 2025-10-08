# capture.py
# Reads a pcap and writes packets.jsonl (one JSON object per packet)
import json
import threading
import time
import subprocess
from collections import defaultdict
from scapy.all import Ether, IP, TCP, UDP, rdpcap, sniff, get_if_list, wrpcap
from flask import Flask, render_template_string, request, redirect, url_for
import requests

app = Flask(__name__)
IDS={"status":"stoped"}


FOLDER = "packets.jsonl"
OUT_FOLDER = "feature.jsonl"
PCAP_LOG = "Total_packets_log.pcap"
#for i in range(2):
#PCAP_FILE = "attack.pcap"
   # i += 1
OUT_FILE = "packets.jsonl"
Proto_map =  {1: "ICMP", 17: "UDP", 6: "TCP"}


def pkt_to_dict(pkt):
    d = {}
    d['time'] = float(pkt.time) if hasattr(pkt, 'time') else None

    # Ethernet
    if Ether in pkt:
        #eth = pkt[Ether]
        d['eth_src'] = pkt[Ether].src
        d['eth_dst'] = pkt[Ether].dst

    # IP
    if IP in pkt:
        ip = pkt[IP]
        d['src_ip'] = ip.src
        d['dst_ip'] = ip.dst
        d['proto'] = Proto_map.get(ip.proto, str(ip.proto))

    # TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        d['src_port'] = int(tcp.sport)
        d['dst_port'] = int(tcp.dport)
        d['flags'] = str(tcp.flags)
        # payload length
        d['payload_len'] = len(bytes(tcp.payload))
        if pkt[TCP].dport == 1883:
            raw = bytes(pkt[TCP].payload)
            if raw :
                try:
                    txt = raw.decode('utf-8' , errors='ignore')
                    if "TOPIC:" in txt:
                        start = txt.find("TOPIC:") + len ("TOPIC:")
                        end = txt.find(";" , start)
                        if end == -1:
                            end = len(txt)
                        topic = txt[start:end].strip()
                        if topic:
                            d["mqtt_topic"] = topic

                except Exception:
                    pass
    # UDP
    if UDP in pkt:
        udp = pkt[UDP]
        d['src_port'] = int(udp.sport)
        d['dst_port'] = int(udp.dport)
        d['payload_len'] = len(bytes(udp.payload))

    # total length if available
    try:
        d['len'] = int(pkt.len)
    except Exception:
        pass
    #print(pkt)
    return d

def main():
    #pkts = rdpcap(PCAP_FILE)

    #pkts = rdpcap(PCAP_FILE)
    print("[+] capturing all packages on default interface ...")
    if_list = get_if_list()
    pkts = sniff(iface=if_list,timeout=40)
    with open(PCAP_LOG, "w") as f:
        wrpcap(PCAP_LOG, pkts)
    with open(OUT_FILE, "w") as f:
        for idx, p in enumerate(pkts):
            obj = pkt_to_dict(p)
            obj["pkt_index"] = idx
            f.write(json.dumps(obj) + "\n")
    print("[+] Wrote", OUT_FILE, "with", len(pkts), "entries")


def count_packets():
    least_pkt_index = defaultdict(int)
    count = defaultdict(int)
    ds_port = defaultdict(set)
    Protocol = defaultdict(set)
    syn_count = defaultdict(int)
    dns_queries = defaultdict(int)
    total_len = defaultdict(int)
    mqtt_topics = defaultdict(set)
    mqtt_publish_count = defaultdict(int)
    mqtt_first_ts = defaultdict(lambda: None)
    mqtt_last_ts = defaultdict(lambda: None)
    with open(FOLDER, 'r') as f:
        #data = f.read()
        for line in f:
            try:
                packet = json.loads(line) 
                src_ip = packet.get("src_ip", None)
                dport = packet.get("dst_port", None)
                Proto = packet.get("proto",None)
                syn = packet.get ("flags", "")
                dns_queries_count = packet.get("dst_port", None)
                length = packet.get("len", 0)
                topic = packet.get("mqtt_topic", None)
                ts = packet.get("time", None)
                pkt_index = packet.get("pkt_index", None)
                #print(pkt_index)
                if src_ip and pkt_index is not None:
                    least_pkt_index[src_ip] = pkt_index
                if src_ip:          
                    count[src_ip] += 1
                    if dport:
                        ds_port[src_ip].add(dport)
                    if Proto:
                        Protocol[src_ip].add(Proto)
                    if src_ip and "S" in syn:
                        syn_count[src_ip] += 1
                    if dns_queries_count == 53:
                        dns_queries[src_ip] += 1
                    #if pkt_index:
                    #    pkt_indexs[src_ip] += 1
                    if topic:
                        mqtt_topics[src_ip].add(topic)
                        mqtt_publish_count[src_ip] += 1
                        if ts is not None:
                            if mqtt_first_ts[src_ip] is None or ts < mqtt_first_ts[src_ip]:
                                mqtt_first_ts[src_ip] = ts
                            if mqtt_last_ts[src_ip] is None or ts > mqtt_last_ts[src_ip]: 
                                mqtt_last_ts[src_ip] = ts

                    total_len[src_ip] += length
                        
            except json.JSONDecodeError:
                continue
        #print(count)
    with open(OUT_FOLDER, 'a+') as f:
        for src_ip in count:
            avg_len = total_len[src_ip] / count[src_ip] if count[src_ip] else 0

            pub_count = mqtt_publish_count[src_ip]
            if pub_count > 0 and mqtt_first_ts[src_ip] is not None and mqtt_last_ts[src_ip] is not None:
                duration_seconds = max(1.0, mqtt_last_ts[src_ip] - mqtt_first_ts[src_ip])
                duration_minutes = max(1.0, duration_seconds / 60.0)  # avoid division by <1 minute
                publish_rate = pub_count / duration_minutes
            else:
                publish_rate = 0.0
            features = {
                "src_ip" : src_ip,
                "Packet_count" : count[src_ip],
                "Protocol" : list(Protocol[src_ip]),
                "unique_dst_ports" : len(ds_port[src_ip]),
                "syn_count" : syn_count[src_ip],
                "dns_queries_count" : dns_queries[src_ip],
                "avg_pkt_size" : avg_len,
                "mqtt_publish_count": pub_count,
                "mqtt_unique_topics": len(mqtt_topics[src_ip]),
                "mqtt_publish_rate_per_min": round(publish_rate, 2),
                "pkt_index" : least_pkt_index[src_ip]

            }
            f.write(json.dumps(features) + "\n")

#def unique_dst_port_count():


def rules():
    FOLDER = "feature.jsonl"
    OUT_FOLDER = "alerts.jsonl"
    alarts = []

    with open(FOLDER, 'r') as f:
        for line in f:
            fetchs = json.loads(line)
            pkt_index = fetchs.get("pkt_index")
            src = fetchs["src_ip"]
            pkt_count = fetchs["Packet_count"]
            uniq_ports = fetchs["unique_dst_ports"]
            syn_count = fetchs["syn_count"]
            dns_queries = fetchs["dns_queries_count"]
            avg_len = fetchs['avg_pkt_size']
            mqtt_unique_topics = fetchs.get("mqtt_unique_topics", 0)
            mqtt_rate = fetchs.get("mqtt_publish_rate_per_min", 0.0)


      #...adjustr your thrushold  here.....
            MQTT_TOPICS_THRESHOLD = 20
            MQTT_RATE_THRESHOLD = 30.0
            PORT_SCAN_THRESHOLD = 20
            FLOOD_PKT_THRESHHOLD = 100
            SYN_RATIO_THRUSHOLD = 20
            SYN_ABS_THRUSHOLD = 20
            DNS_QUERIES_THRUSHOLD = 50
            LARGE_PKT_AVG = 1200
            TINY_PKT_AVG = 60
            DEDUP_SECONDS = 60

            if uniq_ports > PORT_SCAN_THRESHOLD:
                alarts.append({
                    "src" : src,
                    "alert" : "PORT SCAN",
                    "severity":"Medium",
                    "details" : f"connected to {uniq_ports} different ports",
                    "evidence": pkt_index
                })
            if pkt_count > FLOOD_PKT_THRESHHOLD:
                alarts.append({
                    "src" : fetchs["src_ip"],
                    "alert" : "FLOOD",
                    "severity":"HIGH",
                    "details" : f"sent {pkt_count} number of pakets",
                    "evidence": pkt_index
                })
            if pkt_count > 0 and (syn_count / pkt_count) > 0.5 and syn_count > SYN_RATIO_THRUSHOLD:
                alarts.append({
                    "src" : fetchs["src_ip"],
                    "alert" : " SYN FLOOD",
                    "severity":"HIGH",
                    "details" : f"sent {syn_count} numbers of SYN pakets",
                    "evidence": pkt_index
                })
            if dns_queries > DNS_QUERIES_THRUSHOLD:
                alarts.append({
                    "src" : fetchs["src_ip"],
                    "alert" : "suspicions DNS queries",
                    "severity":"Medium",
                    "details" : f"sent {dns_queries}  suspicions DNS queries",
                    "evidence": pkt_index
                })    
            if avg_len > LARGE_PKT_AVG:
                alarts.append({
                    "src" : fetchs["src_ip"],
                    "alart" : "LARGE_PKT",
                    "severity":"Low",
                    "details" : f"avg size {avg_len:.1f}",
                    "evidence": pkt_index
                })
            if mqtt_unique_topics > MQTT_TOPICS_THRESHOLD:
                alarts.append({
                    "src_ip": src, 
                    "alert": "MQTT_ABUSE_TOPICS", 
                    "severity":"HIGH",
                    "details": f"{mqtt_unique_topics} unique topics",
                    "evidence": pkt_index
                })
            if mqtt_rate > MQTT_RATE_THRESHOLD:
                alarts.append({
                    "src_ip": src,
                    "alert": "MQTT_ABUSE_RATE", 
                    "severity":"HIGH",
                    "details": f"{mqtt_rate} msgs/min",
                    "evidence": pkt_index
                })
            if mqtt_unique_topics > MQTT_TOPICS_THRESHOLD and dns_queries > 20:
                alarts.append({
                     "src_ip": src,
                     "alert": "MQTT_ABUSE_RATE",
                     "severity":"HIGH",
                     "detail": f"both mqtt_unique_topics  and  dns_queries  are above treshold",
                     "evidence": pkt_index
                })


        # small in-memory dedup store: {(src,rule): last_ts}
    recent_alarts = {}

    def write_alarts(alarts):
        """Append alert dict to ALERT_FILE and update dedup store."""
        for alart in alarts:
            key = (alart.get("src_ip"), alart.get("alarts"))
            last = recent_alarts.get(key)
            now = time.time()
            if last and (now - last) < DEDUP_SECONDS:
                return  # skip duplicate alarts within dedup window
        # record time and write
            alart["time"] = now
            recent_alarts[key] = now
        with open(OUT_FOLDER, "a") as f:
            f.write(json.dumps(alarts) + "\n")
        for line in alarts:
            print("alarts:", alarts[line], alarts["src_ip"], "-", alarts.get("details", ""))


    with open(OUT_FOLDER, 'a+') as f:
        print("[+] Running rules on", FOLDER )
        write_alarts(alarts)
        for line in range(len(alarts)):
            f.write(json.dumps(alarts[line]) + "\n")
    print(f"[+] wrote {OUT_FOLDER} with {len(alarts)} alarts")

def calls():
    main()
    print("[+] specifing each pakets featuer....")
    count_packets()
    print("[+] Cheking for any attakes....")
    rules()
    subprocess.run(["python", "extract_evidence.py"])

def background_ids():
    """Run IDS capture in a loop while status is running."""
    while IDS["status"] == "running":
        calls()  # your capture function
        time.sleep(1)  # small delay to prevent tight loop

@app.route('/IDS_status', methods=['POST'])
def receive_ids_status():
    # Get the JSON data from the request
    data = request.get_json()
    IDS["status"]= data.get('value')
    print(IDS)
    thread = threading.Thread(target=background_ids, daemon=True)
    thread.start()
    return  {"message": "Status updated successfully"}, 200

if __name__ == "__main__":
    print("we are liseting ")
    app.run(debug=True, host='0.0.0.0', port=5000)
