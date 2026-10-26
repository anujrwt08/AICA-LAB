# ThreatShield AI - Intrusion Detection System

ThreatShield AI is a state-of-the-art Anomaly-based Intrusion Detection System (AIDS). It visualizes live network traffic, detects malicious actors using Machine Learning models, and provides a real-time command center for network security monitoring.

## Features

- **Live Network Topology Map**: A premium, auto-discovering 2D network graph that visualizes traffic flow between internal nodes and external threats.
- **Real-Time Anomaly Logs**: A streaming log feed that flags malicious packets (DDoS, Port Scans, etc.) the exact moment they hit the network.
- **Model Insights**: In-depth analytics and metrics from the Machine Learning models powering the threat detection (Champion Model: XGBoost).
- **Dark Mode UI**: A highly polished, professional cyber-security command center aesthetic.

## System Architecture
<img width="2816" height="1536" alt="ThreatShield Architecture" src="https://github.com/user-attachments/assets/62d682de-a9f4-42b7-a524-4f441b24867e" />

The project operates across a distributed 3-node architecture:
1. **Network Sniffer (Kali Linux VM)**: A Python/Scapy agent that captures raw network packets on the interface, filters ambient noise, and extracts core features (Protocol, Length, TCP/UDP/ICMP flags).
2. **Machine Learning Backend (Windows/FastAPI)**: Ingests the packet telemetry, scales features using `MinMaxScaler`, runs inference via a trained XGBoost model, and broadcasts results over WebSockets.
3. **Frontend Dashboard (Windows/React)**: Connects to the WebSocket pipeline to render live metrics and highlight threshold breaches in real-time.

---

## 🚀 Frontend Setup (React)

The frontend is built using React, Vite, Recharts, and ForceGraph2D.

### Prerequisites
- Node.js (v16+)
- npm or yarn

### Installation
1. Open a terminal and navigate to the `aids-frontend` directory.
2. Install the dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
```bash
npm run dev
```


4. Open `http://localhost:5173` in your browser.

---

## 🧠 Backend / Machine Learning Setup (FastAPI)

The backend uses FastAPI for live traffic classification and anomaly detection.

### Prerequisites

* Python 3.10+
* The model artifacts in the backend root (`aids-backend/`):
* `xgboost_aids.json`
* `aids_scaler.pkl`



### Installation

1. Open a terminal and navigate to the `aids-backend` directory.
2. Install the required Python packages:
```bash
pip install fastapi uvicorn xgboost scikit-learn joblib pydantic
```


3. Start the backend server (ensure the IP matches your network adapter connecting to the VM):
```bash
uvicorn main:app --host 192.168.136.1 --port 8000 --reload
```



### API Endpoints

* **`POST /api/v1/traffic`**: Accepts packet metadata, scales features, runs inference, and broadcasts results.
* **`WebSocket /ws/live`**: Client endpoint for receiving live anomaly updates and system metrics.

---

## 🛡️ Explainable AI (XAI) Threat Defense Console (`kali.py`)

The console GUI (`kali.py`) provides live packet sniffing, automatic adapter detection (Wi-Fi, Ethernet, Loopback, eth0), safe threat simulations, and real-time **Explainable AI (XAI)** threat analysis.

### Features
- **Adapter Detection**: Automatically detects active network interfaces on Windows and Linux without crashing.
- **Explainable AI (XAI) Threat Inspector**: Identifies what type of attack occurred (UDP Flood, ICMP Ping of Death, DNS Burst, HTTPS Exfiltration, DDoS, TCP SYN Flood) and explains **why and how** it was identified as an attack.
- **Feature Baseline Comparison**: Compares observed packet size, protocol, and transport flags against normal baseline thresholds (RFC 791 / IEEE 802.3 MTU).
- **Presentation Dossier**: Generates a complete Explainable AI threat briefing suitable for academic presentations and defense evaluations.

### Execution
Run the console on your host or VM:
```bash
python kali.py
```

---

## ⚔️ Safe Threat Simulation Lab

Simulate realistic attacks safely without transmitting malicious payloads:
1. **UDP Volumetric Flood**: Datagrams exceeding standard 1500B MTU limit.
2. **ICMP Ping of Death / Echo Flood**: Oversized ICMP control packets.
3. **DNS Query Burst**: Rapid high-frequency UDP resolution queries.
4. **HTTPS Payload Spike**: Out-of-bounds TCP segment payload indicating exfiltration.
5. **Distributed DDoS Multi-Source**: Coordinated volumetric stream from randomized IP prefixes.
6. **TCP SYN Flood / Port Reconnaissance**: Minimal zero-payload TCP probes.
7. **Normal Web Traffic**: Legitimate baseline traffic.



---

## Repository Structure

```text
AIDS/
├── aids-backend/      # FastAPI server, XGBoost model, and Data Scaler
├── aids-frontend/     # React/Vite interactive command dashboard
└── aids-sniffer/      # Scapy packet capture and threat simulation scripts
```
