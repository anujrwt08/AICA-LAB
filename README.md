# ThreatShield AI - Anomaly-Based Intrusion Detection System (AIDS)

ThreatShield AI is an enterprise-grade Anomaly-Based Intrusion Detection System (AIDS) combining Machine Learning (XGBoost) with Explainable AI (XAI) to detect, classify, and explain zero-day and volumetric cyber attacks in real time.

---

## 🚀 Key Features

- **🛡️ Persistent Incident & Anomaly Logs**:
  - **Attacks-Only Focus**: Strictly logs detected network anomalies and attacks; benign baseline traffic is filtered out so critical threat bursts are never pushed off-screen.
  - **Forensic Export (CSV & JSON)**: One-click export of recorded incident history into UTF-8 CSV (compatible with Excel/Pandas) or structured JSON for post-incident reporting and SIEM ingestion.
  - **Explainable AI (XAI) Root-Cause Forensics**: Click "Explain (XAI)" on any incident to inspect why and how XGBoost classified the attack, review feature-level baseline deviations, identify triggered security rules, and read defense mitigation guidance.
  - **Instant Search & Severity Filtering**: Filter incident history by Source IP, Destination IP, Protocol, Attack Type, or Severity (`CRITICAL`, `HIGH`, `MEDIUM`).
- **🌐 Dynamic Network Topology Map**: Real-time 2D force-directed graph displaying active network nodes, packet trajectories, and attacker subnet links.
- **⚡ Live Threat Dashboard**: Streaming charts showing XGBoost reconstruction loss against dynamic alert thresholds (500.0) with real-time throughput metrics.
- **🧠 Model Insights**: Comprehensive evaluation metrics of the XGBoost production classifier, feature importance rankings, and confusion matrices.
- **💻 Desktop Defense Console (`kali.py`)**: Tkinter-based GUI agent for live packet sniffing, automatic network interface discovery, and controlled attack simulation.

---

## 🏗️ System Architecture

```text
  ┌────────────────────────┐         ┌────────────────────────┐
  │  Network Sniffer       │         │  FastAPI ML Backend    │
  │  (kali.py / VM)        │ ──────> │  (Port 8000)           │
  │  • Scapy Raw Ingress   │  HTTP   │  • XGBoost Classifier  │
  │  • Feature Extraction  │  POST   │  • MinMaxScaler        │
  │  • Attack Simulations  │         │  • XAI Engine & Store  │
  └────────────────────────┘         └───────────┬────────────┘
                                                 │
                                                 │ WebSocket /ws/live
                                                 │ REST /api/v1/anomalies
                                                 v
                                     ┌────────────────────────┐
                                     │  ThreatShield Frontend │
                                     │  (React + Vite : 5173) │
                                     │  • Incident History    │
                                     │  • CSV / JSON Export   │
                                     │  • XAI Root-Cause Modal│
                                     │  • Topology & Insights │
                                     └────────────────────────┘
```

The system operates across a coordinated pipeline:
1. **Packet Capture / Simulator (`kali.py`)**: Sniffs live packets or safely generates synthetic attack signatures (UDP Floods, ICMP Echo Floods, DNS Amplification, HTTPS Spikes, DDoS, SYN Scans).
2. **FastAPI ML & XAI Engine (`aids-backend`)**: Normalizes features using `aids_scaler.pkl`, computes anomaly confidence with `xgboost_aids.json`, generates feature-level explanations, logs attacks to memory, and broadcasts via WebSockets.
3. **React SOC Command Center (`aids-frontend`)**: Visualizes real-time loss scores, renders live topology, and maintains persistent attack history with forensic export tools.

---

## 🏁 Quick Start

### 1. Launch All Services Together
Run the unified launcher from the project root:
```bash
python run_all.py
```
This automatically launches:
- **FastAPI Backend**: `http://localhost:8000`
- **React Frontend**: `http://localhost:5173`

---

### 2. Manual Setup

#### Backend Setup (`aids-backend`)
```bash
cd aids-backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend Setup (`aids-frontend`)
```bash
cd aids-frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

#### Desktop Console & Simulation Lab (`kali.py`)
```bash
python kali.py
```

---

## 📡 Backend API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check endpoint returning backend status. |
| `POST` | `/api/v1/traffic` | Ingests packet telemetry, computes ML inference, and broadcasts results. |
| `GET` | `/api/v1/anomalies` | Retrieves persistent list of recorded attack incidents (`limit=1000`). |
| `DELETE` | `/api/v1/anomalies` | Clears recorded attack history across backend and clients. |
| `GET` | `/api/v1/anomalies/export?format=csv\|json` | Downloads recorded attack history as CSV or JSON directly from the API. |
| `WebSocket` | `/ws/live` | WebSocket stream broadcasting real-time packet evaluations. |

### Sample Packet Ingestion Payload (`POST /api/v1/traffic`)
```json
{
  "src_ip": "192.168.1.105",
  "dst_ip": "10.0.0.1",
  "proto": 17,
  "length": 3400,
  "is_tcp": 0,
  "is_udp": 1,
  "is_icmp": 0,
  "simulation_type": "udp_flood"
}
```

---

## ⚔️ Supported Attack Simulations

The built-in **Safe Threat Simulation Lab** enables demonstration of real attack patterns without transmitting destructive payloads:

1. **UDP Volumetric Flood**: Datagrams exceeding the standard 1,500-byte Ethernet MTU limit on connectionless protocol UDP.
2. **ICMP Ping of Death / Echo Flood**: Oversized ICMP control packets designed to exhaust host network processing buffers.
3. **DNS Query Burst / Amplification**: High-frequency repetitive UDP queries targeting resolution infrastructure.
4. **HTTPS Payload Spike / Data Exfiltration**: Out-of-bounds TCP payload segments exceeding normal TLS record chunks.
5. **Distributed Denial of Service (DDoS)**: Coordinated volumetric streams from randomized/spoofed source subnet pools.
6. **TCP SYN Flood / Port Reconnaissance**: Minimal zero-payload TCP probes scanning for vulnerable listening ports.
7. **Normal Baseline Traffic**: Compliant RFC 791 / IEEE 802.3 packets for baseline validation.

---

## 📁 Repository Structure

```text
AICA-LAB/
├── aids-backend/              # FastAPI server, ML models & scalers
│   ├── main.py                # Core REST API, WebSockets & XAI logic
│   ├── simulate_traffic.py    # Headless background traffic generator
│   ├── xgboost_aids.json      # Trained production XGBoost classifier
│   ├── aids_scaler.pkl        # Fitted MinMaxScaler artifact
│   └── requirements.txt       # Python dependencies
├── aids-frontend/             # React 19 + Vite dashboard
│   ├── src/
│   │   ├── components/        # TelemetryTable, AnomalyChart, MetricsRibbon, Sidebar
│   │   ├── hooks/             # useThreatWebSocket hook with local persistence
│   │   └── pages/             # AnomalyLogs, Dashboard, NetworkTopology, ModelInsights
│   └── package.json           # Frontend dependencies
├── kali.py                    # Explainable AI Desktop Console & Ingress Sniffer
├── run_all.py                 # Unified concurrent server launcher
├── start.bat                  # One-click Windows batch startup script
└── README.md                  # System documentation
```
