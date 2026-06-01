# 🔍 ThreatWatch — Threat Intelligence Dashboard

> Investigate suspicious IPs, domains and file hashes against multiple threat intelligence sources in seconds. Built for security analysts, incident responders and penetration testers.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-3.1-lightgrey)
![Security](https://img.shields.io/badge/Security-Threat%20Intelligence-red)
![Live](https://img.shields.io/badge/Status-Live-brightgreen)

## 🌐 Live Demo
**[Try it now →](https://threatwatch-3vm7.onrender.com)**

> Note: First load may take 30-60 seconds as the free server wakes up.

---

## 📌 Overview

Every day security analysts and incident responders face the same question:

> "Is this IP address, domain or file malicious?"

ThreatWatch answers that question in seconds by querying multiple threat intelligence databases simultaneously and presenting the findings in a clean unified dashboard.

This is exactly what SOC analysts do during incident response and what penetration testers do during reconnaissance.

---

## ✨ Features
🦠 VirusTotal Integration  → Checks against 70+ antivirus engines
🚨 AbuseIPDB Integration   → Cross-references abuse reports database
🌍 IPInfo Integration      → Geolocation and network intelligence
🎯 Auto Detection          → Automatically detects IP, domain or hash
📊 Threat Scoring          → 0-100 threat score with risk levels
🕐 Recent Searches         → History of recent investigations
⚡ Real Time Analysis      → Results in seconds

---

## 🚀 Live Demo

Visit: **https://threatwatch-3vm7.onrender.com**

### Test with these examples:

| Query | Type | Expected Result |
|-------|------|----------------|
| `8.8.8.8` | IP | Clean — Google DNS |
| `185.220.101.45` | IP | Malicious — Tor exit node |
| `google.com` | Domain | Clean |
| `malware.com` | Domain | Suspicious |

---

## 🧠 How It Works
User enters IP / Domain / Hash
↓
Auto detection (IP vs domain vs hash)
↓
Parallel API calls:
→ VirusTotal (70+ AV engines)
→ AbuseIPDB (abuse reports)
→ IPInfo (geolocation)
↓
Threat score calculated (0-100)
↓
Results displayed in dashboard

### Threat Score Calculation
VirusTotal malicious detections → up to 60 points
VirusTotal suspicious detections → up to 20 points
AbuseIPDB confidence score → up to 20 points
0-4   → CLEAN
5-19  → LOW
20-39 → MEDIUM
40-69 → HIGH
70+   → CRITICAL

---

## 📊 What Gets Analyzed

### For IP Addresses
- VirusTotal detection rate across 70+ engines
- AbuseIPDB confidence score and total reports
- Geolocation (city, country, coordinates)
- ISP and organization info
- Tor exit node detection
- Last reported date

### For Domains
- VirusTotal detection rate
- Registrar information
- Domain creation date
- Reputation score

### For File Hashes (MD5/SHA1/SHA256)
- VirusTotal detection rate
- File name and type
- File size
- Malware classification

---

## 🗂️ Project Structure
ThreatWatch/
├── app.py              ← Flask web application
├── threat_intel.py     ← Threat intelligence engine
├── requirements.txt    ← Dependencies
├── Procfile            ← Render deployment config
│
└── templates/
├── index.html      ← Search dashboard
└── results.html    ← Analysis results page

---

## 🛠️ Tech Stack

- **Python** — core language
- **Flask** — web framework
- **Requests** — API calls to threat intelligence sources
- **VirusTotal API** — 70+ antivirus engine results
- **AbuseIPDB API** — IP abuse reports database
- **IPInfo API** — geolocation and network data
- **Render** — cloud deployment

---

## 🔐 Security Concepts Demonstrated
Threat Intelligence  → Querying known malicious indicator databases
IOC Analysis         → Investigating Indicators of Compromise
OSINT                → Open Source Intelligence gathering
Incident Response    → Rapid triage of suspicious activity
Reconnaissance       → Network and domain intelligence gathering

---

## 🚀 Run Locally

### Requirements
- Python 3.8+
- Free API keys from VirusTotal, AbuseIPDB and IPInfo

### Installation

```bash
# Clone the repository
git clone https://github.com/PrinceOseiBonsu/ThreatWatch.git
cd ThreatWatch

# Install dependencies
pip install -r requirements.txt

# Set environment variables
set VIRUSTOTAL_API_KEY=your_key_here
set ABUSEIPDB_API_KEY=your_key_here
set IPINFO_API_KEY=your_key_here

# Run the app
python app.py
```

Then open your browser at:
http://127.0.0.1:5000

---

## 🔮 Coming Soon

- [ ] Bulk IP scanning
- [ ] Export results as PDF report
- [ ] WHOIS lookup integration
- [ ] Shodan API integration
- [ ] Email header analysis

---

## 👨🏾‍💻 Author

**Prince Osei Bonsu**
Computer Science & Cybersecurity — Voorhees University
GPA: 4.0/4.0

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/prince-osei-bonsu)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black)](https://github.com/PrinceOseiBonsu)
[![Project 1](https://img.shields.io/badge/Project%201-AI%20Phishing%20Detector-brightgreen)](https://ai-phishing-email-detector-mfas.onrender.com)
[![Project 2](https://img.shields.io/badge/Project%202-VaultScan-orange)](https://github.com/PrinceOseiBonsu/VaultScan)

---

*Built as part of a deliberate learning journey toward a career in penetration testing and offensive security*
