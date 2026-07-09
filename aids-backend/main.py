from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import xgboost as xgb
import joblib
import numpy as np
import json
import asyncio
import time

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load production ML assets
model = xgb.XGBClassifier()
model.load_model("xgboost_aids.json")
scaler = joblib.load("aids_scaler.pkl")

class PacketData(BaseModel):
    src_ip: str
    dst_ip: str
    proto: int
    length: int
    is_tcp: int
    is_udp: int
    is_icmp: int

active_connections = []

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        active_connections.remove(websocket)

@app.post("/api/v1/traffic")
async def receive_traffic(data: PacketData):
    # 1. Align features for the model matching the training array
    raw_features = np.array([[data.proto, data.length, data.is_tcp, data.is_udp, data.is_icmp]], dtype=np.float32)
    
    # 2. Scale using the production scaler pipeline
    scaled_features = scaler.transform(raw_features)
    
    # 3. Perform live classification inference
    prediction = int(model.predict(scaled_features)[0])
    probability = float(model.predict_proba(scaled_features)[0][1])
    
    is_anomaly = prediction == 1
    attack_type = "Malicious Exploit Activity" if is_anomaly else "Normal Baseline"
    
    # 4. Construct payload for the frontend UI (including current Unix timestamp in milliseconds)
    payload = {
        "metrics": {
            "src_ip": data.src_ip,
            "dst_ip": data.dst_ip,
            "proto": data.proto,
            "length": data.length,
            "is_tcp": data.is_tcp,
            "is_udp": data.is_udp,
            "is_icmp": data.is_icmp,
            "timestamp": int(time.time() * 1000)
        },
        "anomaly": is_anomaly,
        "attack_type": attack_type,
        "score": probability * 100 
    }
    
    # 5. Broadcast to connected UI dashboards
    for connection in active_connections:
        try:
            await connection.send_text(json.dumps(payload))
        except Exception:
            active_connections.remove(connection)
            
    return {"status": "processed", "anomaly": is_anomaly, "confidence": probability}