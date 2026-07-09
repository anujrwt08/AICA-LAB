# ThreatShield AI - Intrusion Detection System

ThreatShield AI is a state-of-the-art Network Anomaly Detection dashboard. It visualizes live network traffic, detects malicious actors using Machine Learning models, and provides a real-time command center for network security monitoring.

## Features

- **Live Network Topology Map**: A premium, auto-discovering 2D network graph that visualizes traffic flow between internal nodes and external threats.
- **Real-Time Anomaly Logs**: A streaming log feed that flags malicious packets (DDoS, Port Scans, etc.) the exact moment they hit the network.
- **Model Insights**: In-depth analytics and metrics from the Machine Learning models (Random Forest, XGBoost, Neural Networks) powering the threat detection.
- **Dark Mode UI**: A highly polished, professional cyber-security command center aesthetic.

## System Architecture

The project consists of two parts:
1. **Machine Learning Backend (Python)**: Processes network packets, runs them through trained ML classifiers, and streams the results via WebSockets.
2. **Frontend Dashboard (React/Vite)**: Connects to the WebSocket and renders the data in real-time.

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

## 🧠 Backend / Machine Learning Setup (Python)

The backend uses FastAPI for live traffic classification and anomaly detection using a trained XGBoost model.

### Prerequisites
- Python 3.10+
- The model artifacts in the backend root (`aids-backend/`):
  - `xgboost_aids.json`
  - `aids_scaler.pkl`

### Installation
1. Open a terminal and navigate to the `aids-backend` directory.
2. Create and activate a virtual environment (optional but recommended).
3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the backend server (using Uvicorn) from the `aids-backend` directory:
   ```bash
   uvicorn main:app --reload
   ```
   If you want to bind to a specific host and port:
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

### API Endpoints

#### `POST /api/v1/traffic`
Accepts packet metadata, scales the features, runs model inference, and broadcasts the result to connected dashboards.

Example request body:
```json
{
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "proto": 6,
  "length": 128,
  "is_tcp": 1,
  "is_udp": 0,
  "is_icmp": 0
}
```

#### `WebSocket /ws/live`
Use this endpoint from a dashboard client to receive live anomaly updates.

### Notes
- The backend expects the model files to stay next to `main.py`.
- CORS is currently configured to allow all origins.

---

## Repository Structure

```text
AIDS/
├── aids-backend/      # FastAPI backend and Machine Learning models
└── aids-frontend/     # React / Vite frontend dashboard
```
