#!/usr/bin/env python3
from scapy.all import sniff, ARP, IP, Raw
from datetime import datetime
import json
from flask import Flask
from flask import Flask, render_template, jsonify, request, Response

app = Flask(__name__)

known_ips = {"192.168.1.1", "192.168.1.10"}
log_file = "ids_log.json"

@app.route("/host_ids")
def read():
    with open(log_file, "r") as f:
        data = json.load(f)
    return data


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5050)