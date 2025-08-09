
Description:  
This project is a lightweight, Python-based Intrusion Detection System (IDS) built from scratch to detect common web application attacks.  
It focuses on HTTP traffic analysis and uses custom signature rules to identify suspicious patterns such as SQL Injection, Cross-Site Scripting (XSS), Command Injection, and Path Traversal.  
Unlike general-purpose IDS tools like Snort or Suricata, this system is tailored for web-only threats, making it easy to customize and deploy in small to medium environments.

---

## 🛠 Basic Steps for the Project

| Step | What to Do | Output |
|------|------------|--------|
| 1. Learn basics | Understand HTTP requests/responses and common web attacks (SQLi, XSS, path traversal). | You can explain how attacks work. |
| 2. Packet capture | Learn to use Python scapy or pyshark to capture HTTP traffic. | A Python script that prints captured HTTP requests. |
| 3. Parsing | Extract URL, headers, and body from captured packets. | Structured data (JSON/dict) for each HTTP request. |
| 4. Detection rules | Write regex or string-matching rules for a few attacks. | A rules.json file with patterns. |
| 5. Alerting | Make a function to log or print alerts when patterns match. | Alerts appear in terminal or saved to a log file. |
| 6. Testing | Use DVWA or OWASP Juice Shop to generate attacks and test detection. | Alerts trigger correctly on test attacks. |
| 7. Packaging | Put everything into one script or small project. Optionally add Docker. | A runnable IDS project. |

---

## 📚 Learning Path
| Week | Topics to Learn | Practice |
|------|-----------------|----------|
| **Week 1** | HTTP basics, web attack types (SQLi, XSS, etc.) | Read OWASP Top 10, try attacks on DVWA |
| **Week 2** | Python packet capture (`scapy`, `pyshark`) | Capture HTTP traffic from browser to local server |
| **Week 3** | Regex & detection logic | Write simple regex to detect `<script>` or `OR 1=1` |
| **Week 4** | Integrating capture + detection + alerts | Test with DVWA, package into final script 


## 📌 Future Improvements
- Add anomaly-based detection using ML
- Build a web dashboard for real-time alerts
- Integrate with firewall rules for blocking malicious IPs


