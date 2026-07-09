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

<<<<<<< HEAD
---

## 🕵️♂️ Network Sniffer Setup (Kali Linux)

The sniffer runs on a separate machine or VM to monitor active network interfaces and push telemetry to the backend.

### Prerequisites

* Kali Linux (or any Debian-based system)
* Root/Sudo privileges (required for raw packet capture)

### Installation & Execution

1. Open a terminal in Kali Linux and navigate to the `aids-sniffer` directory.
2. Install Scapy:
```bash
pip3 install scapy
```


3. Launch the live sniffer (Ensure you update the backend IP in the script if it changes):
```bash
sudo python3 aids_sniffer.py
```



---

## ⚔️ Threat Simulation & Testing

To validate the ML model's accuracy without executing actual malware, the repository includes controlled anomaly generation scripts. These scripts craft out-of-distribution packets designed to trigger the Anomaly-based IDS.

Run these scripts from your **Kali Linux VM** while the sniffer and backend are active:

1. **Multi-Vector Threat Suite**
Sends 5 distinct packet types (including volumetric UDP bursts and malformed TCP structures) to test classification boundaries.
```bash
sudo python3 advanced_test_suite.py
```


2. **Spoofed DDoS Simulation**
Generates anomalous payloads from an array of randomized, spoofed IP addresses to test the frontend UI's multi-actor rendering.
```bash
sudo python3 simulate_multi_ip.py
=======
Example request body:
```json
{
  "src_ip": "192.168.1.",
  "dst_ip": "192.168.1.0",
  "proto": 6,
  "length": 128,
  "is_tcp": 1,
  "is_udp": 0,
  "is_icmp": 0
}
>>>>>>> 4966130b1440d999535c0b9305e5d671fbc5a31d
```



---

## Repository Structure

```text
AIDS/
├── aids-backend/      # FastAPI server, XGBoost model, and Data Scaler
├── aids-frontend/     # React/Vite interactive command dashboard
└── aids-sniffer/      # Scapy packet capture and threat simulation scripts
```
