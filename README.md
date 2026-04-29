# 🛡️ HNG Anomaly Detection Engine

A production-grade real-time DDoS and anomaly detection system built for the HNG DevOps Track Stage 3.  
The system detects abnormal traffic patterns using statistical analysis and blocks malicious IPs at the kernel level using `iptables`.

---

## 🔗 Live Links

- **Server IP:** `3.81.24.112`
- **Metrics Dashboard:** http://3.81.24.112/dashboard/
- **Application Root:** http://3.81.24.112/
- **GitHub Repository:** https://github.com/JULIET-JULIET632/hng-anomaly-detector

---

## ⚙️ Architecture Overview

The system is built using a modular, containerized architecture:

- Nginx reverse proxy logs real-time traffic
- Python daemon processes logs continuously
- Statistical engine builds dynamic traffic baselines
- Anomaly detector identifies suspicious activity
- iptables enforces kernel-level blocking
- Docker Compose orchestrates all services

---

## 🐍 Language Choice — Python

Python was chosen because of:

- Fast development speed
- Clean and readable syntax
- Strong standard library support
- Efficient data structures like `deque` for sliding window processing
- No need for heavy external dependencies

---

## 📊 Sliding Window Mechanism

The system tracks requests using a 60-second rolling window:

- Each request timestamp is appended to a deque
- Old timestamps older than 60 seconds are removed automatically
- Request rate is calculated as:

requests per second = len(window) / 60

---

## 📈 Baseline Engine (Adaptive Learning)

Instead of static thresholds, the system learns traffic behavior dynamically:

- 30-minute rolling statistical window
- Hour-based traffic segmentation
- Mean and standard deviation recalculated every 60 seconds
- Cold-start protection for new traffic

---

## 🚨 Anomaly Detection Logic

The system triggers alerts when:

- Z-score > 3.0  
- OR request rate > 5× baseline mean  
- OR error surge detected (tightened thresholds)

---

## 🔒 iptables Enforcement

Blocking rule:

iptables -I INPUT 1 -s <IP> -j DROP

### Strategy:
- Kernel-level blocking
- Immediate enforcement
- Highest priority rule insertion

---

## 🚀 Deployment Instructions

### 1. Install Docker
```bash
curl -fsSL https://get.docker.com | sh
apt install -y docker-compose
