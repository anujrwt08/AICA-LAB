# AIDS Backend

FastAPI backend for live traffic classification and anomaly detection using a trained XGBoost model.

## What it does

- `POST /api/v1/traffic` accepts packet metadata, scales the features, runs model inference, and broadcasts the result to connected dashboards.
- `WebSocket /ws/live` keeps dashboard clients connected so they can receive live updates.

## Requirements

- Python 3.10 or newer
- The model artifacts in the project root:
  - `xgboost_aids.json`
  - `aids_scaler.pkl`

## Install

Create and activate a virtual environment, then install dependencies:

```bash
pip install -r requirements.txt
```

## Start the backend server

Run the FastAPI app with Uvicorn from the project root:

```bash
uvicorn main:app --reload
```

If you want to bind to a specific host and port:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## API endpoints

### `POST /api/v1/traffic`

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

### `WebSocket /ws/live`

Use this endpoint from a dashboard client to receive live anomaly updates.

## Notes

- The backend expects the model files to stay next to `main.py`.
- CORS is currently configured to allow all origins.