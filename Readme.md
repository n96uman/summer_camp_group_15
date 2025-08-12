# IoT Network-Based IDS & Malware Detection — Team Project

## 📌 Project Overview  
We are developing a **network-based intrusion detection system (IDS)** aimed at monitoring and protecting IoT devices on a home network. The system will include basic malware detection capabilities focusing on known malicious traffic patterns.

---

## 🎯 Project Goals  
- Capture and analyze IoT network traffic  
- Detect intrusions and suspicious activities using rule-based signatures  
- Identify malware-related network behavior (e.g., connections to malicious IPs/domains)  
- Provide clear logging and alerting mechanisms  
- Build a simple dashboard/interface to visualize alerts (optional / stretch goal)  

---

## 🗓 1-Month Progress Plan & Milestones  

| Week   | Objectives                                                                 | Deliverables / Checkpoints                                        | Progress      |
|--------|----------------------------------------------------------------------------|------------------------------------------------------------------|---------------|
| Week 1 | Learn IoT network protocols (MQTT, CoAP, HTTP)                            | Packet capture script running on test environment                | Not Started   |
|        | Setup environment (Python, Scapy, PyShark)                                | Documentation on IoT protocols & initial observations            |               |
| Week 2 | Understand and implement basic IDS rules                                  | Simple rule engine implemented (e.g., match IP blacklist)        | Not Started   |
|        | Flag suspicious IPs, ports, and simple packet payload patterns            | Logged alerts for test scenarios                                  |               |
| Week 3 | Integrate malware detection based on known threat intelligence           | Integration with at least one threat intel source (static blacklist or API) | Not Started   |
|        | Test detection of simulated malware traffic                              | Sample alerts triggered by malicious test traffic                |               |
| Week 4 | Improve logging and alert clarity                                         | Well-documented codebase                                          | Not Started   |
|        | (Optional) Develop a basic dashboard or report generator                  | Summary report of test results                                    |               |
|        | Final testing and documentation                                           | (Optional) Web dashboard or visualization                         |               |

---

## 📚 Learning Path  

| Topic                 | Description                                              | Resources                                                                                  | Progress    |
|-----------------------|----------------------------------------------------------|--------------------------------------------------------------------------------------------|-------------|
| IoT Network Protocols  | Understand MQTT, CoAP, HTTP as used by IoT devices       | [HiveMQ MQTT Essentials](https://www.hivemq.com/mqtt-essentials/), [CoAP Docs](https://coap.technology/) | Not Started |
| Packet Capture & Analysis | Learn packet capture tools and libraries (Scapy, PyShark) | [Scapy Docs](https://scapy.readthedocs.io/), [PyShark Docs](https://kiminewt.github.io/pyshark/)          | Not Started |
| IDS Fundamentals      | Study signature-based IDS concepts and rule writing       | [Suricata Docs](https://suricata.io/documentation/), [Snort Docs](https://snort.org/documents)             | Not Started |
| Malware Detection Basics | Learn how malware behaves on the network and detection strategies | [YARA Docs](https://yara.readthedocs.io/en/stable/), [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) | Not Started |
| Dashboard Development | Build simple web interfaces for alert visualization       | [Flask Docs](https://flask.palletsprojects.com/), [FastAPI Docs](https://fastapi.tiangolo.com/)             | Not Started |

---

## 🛠 Tools & Technologies  
- **Programming:** Python 3.x  
- **Packet Capture:** Scapy, PyShark  
- **Threat Intel:** Static IP/domain blacklists or APIs (e.g., AbuseIPDB)  
- **Testing:** Wireshark, simulated IoT devices or traffic generators  
- Dashboard: simple front-end  

---

## 📚 References 
- [Scapy Documentation](https://scapy.readthedocs.io/en/latest/)  
- [Suricata Rule Writing Guide](https://suricata.readthedocs.io/en/latest/rules/)  
- [AbuseIPDB API](https://docs.abuseipdb.com/)  
- [IoT Protocols Overview (MQTT, CoAP)](https://www.hivemq.com/mqtt-essentials/)  

---

## 📝 Notes  
- This project is a learning exercise focused on foundational concepts and basic implementation.  
- Machine learning and host-based IDS integration are planned for future phases.  

---

Thank you for your guidance and support!  
— Team15
