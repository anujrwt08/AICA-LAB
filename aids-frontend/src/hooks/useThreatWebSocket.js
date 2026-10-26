import { useState, useEffect, useCallback, useRef } from 'react';

const MAX_HISTORY = 50;
const THRESHOLD = 500.0;
const WS_URL = import.meta.env.VITE_WS_URL || (typeof window !== 'undefined' && window.location.hostname ? `ws://${window.location.hostname}:8000/ws/live` : 'ws://localhost:8000/ws/live');
const RENDER_INTERVAL_MS = 250; // Throttle React state updates to 4 times a second for smooth live rendering

export function useThreatWebSocket() {
  const [dataHistory, setDataHistory] = useState([]);
  const [connectionStatus, setConnectionStatus] = useState('Connecting');
  
  const [metrics, setMetrics] = useState({
    totalTraffic: 0,
    detectedAnomalies: 0,
    averageErrorScore: 0,
    currentThreshold: THRESHOLD
  });

  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const renderIntervalRef = useRef(null);
  
  // Keep true state in refs to avoid constant React re-renders for high-frequency streaming
  const historyRef = useRef([]);
  const metricsRef = useRef({
    totalTraffic: 0,
    detectedAnomalies: 0,
    sumScore: 0,
    latestAnomalyType: null
  });

  const connect = useCallback(() => {
    try {
      setConnectionStatus('Connecting');
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnectionStatus('Connected');
        console.log('WebSocket connected to', WS_URL);
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          
          // Robust fallback: if the backend payload is missing the metrics block or the timestamp,
          // we dynamically inject the current real time.
          if (!payload.metrics) {
            payload.metrics = {};
          }
          if (!payload.metrics.timestamp) {
            payload.metrics.timestamp = Date.now() / 1000;
          } else if (payload.metrics.timestamp > 2000000000) {
            // If the backend sends the time in milliseconds (value larger than the year 2033 in seconds),
            // convert it down to seconds because the rest of the app assumes the timestamp is in seconds.
            payload.metrics.timestamp = payload.metrics.timestamp / 1000;
          }
          
          const newEntry = {
            ...payload,
            id: `${payload.metrics.timestamp}-${Math.random().toString(36).substr(2, 9)}`
          };

          historyRef.current = [...historyRef.current, newEntry].slice(-MAX_HISTORY);
          
          const isAnomaly = payload.anomaly === true;
          metricsRef.current.totalTraffic += 1;
          if (isAnomaly) {
            metricsRef.current.detectedAnomalies += 1;
            metricsRef.current.latestAnomalyType = payload.attack_type || 'Threat Detected';
          }
          metricsRef.current.sumScore += (payload.score || 0);

        } catch (err) {
          console.error("Error parsing websocket message", err);
        }
      };

      ws.onclose = () => {
        setConnectionStatus('Disconnected');
        console.log('WebSocket disconnected. Reconnecting in 3s...');
        reconnectTimeoutRef.current = setTimeout(connect, 3000);
      };

      ws.onerror = (error) => {
        console.error('WebSocket Error:', error);
        ws.close();
      };
    } catch (err) {
      console.error("Failed to connect", err);
      setConnectionStatus('Error');
      reconnectTimeoutRef.current = setTimeout(connect, 5000);
    }
  }, []);

  useEffect(() => {
    connect();
    
    // Throttle loop: Flush ref state to React state every 250ms
    renderIntervalRef.current = setInterval(() => {
      setDataHistory([...historyRef.current]);
      
      const totalScore = metricsRef.current.sumScore;
      const count = metricsRef.current.totalTraffic;
      const avgScore = count > 0 ? totalScore / count : 0;
      
      setMetrics({
        totalTraffic: metricsRef.current.totalTraffic,
        detectedAnomalies: metricsRef.current.detectedAnomalies,
        averageErrorScore: avgScore,
        currentThreshold: THRESHOLD,
        latestAnomalyType: metricsRef.current.latestAnomalyType
      });
      
    }, RENDER_INTERVAL_MS);

    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (renderIntervalRef.current) clearInterval(renderIntervalRef.current);
    };
  }, [connect]);

  // Simulated data for testing when the server isn't up
  /*
  useEffect(() => {
    const interval = setInterval(() => {
      if (connectionStatus !== 'Connected') return;
      const isAnomaly = Math.random() > 0.85;
      const score = isAnomaly ? 500 + Math.random() * 400 : Math.random() * 300;
      const mockEvent = {
        data: JSON.stringify({
          metrics: {
            timestamp: Date.now() / 1000,
            src_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
            dst_ip: `10.0.0.${Math.floor(Math.random() * 255)}`,
            proto: Math.random() > 0.5 ? 6 : 17,
            length: Math.floor(Math.random() * 1500)
          },
          anomaly: isAnomaly,
          attack_type: isAnomaly ? 'DDoS' : 'Normal',
          score: score
        })
      };
      wsRef.current?.onmessage(mockEvent);
    }, 100); // 10 updates per second! The UI should not lag because of our throttle
    return () => clearInterval(interval);
  }, [connectionStatus]);
  */

  return {
    dataHistory,
    metrics,
    connectionStatus
  };
}
