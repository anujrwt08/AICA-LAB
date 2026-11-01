import { useState, useEffect, useCallback, useRef } from 'react';

const MAX_HISTORY = 50;
const MAX_ANOMALY_HISTORY = 1000;
const THRESHOLD = 500.0;
const WS_URL = import.meta.env.VITE_WS_URL || (typeof window !== 'undefined' && window.location.hostname ? `ws://${window.location.hostname}:8000/ws/live` : 'ws://localhost:8000/ws/live');
const API_BASE_URL = import.meta.env.VITE_API_URL || (typeof window !== 'undefined' && window.location.hostname ? `http://${window.location.hostname}:8000` : 'http://localhost:8000');
const RENDER_INTERVAL_MS = 250; // Throttle React state updates to 4 times a second for smooth live rendering
const STORAGE_KEY = 'threatshield_anomaly_history';

// Strict filter to guarantee ONLY real attacks are stored in Anomaly History (no safe baseline traffic)
const isGenuineAttack = (item) => {
  if (!item || item.anomaly !== true) return false;
  const attackType = (item.attack_type || '').toLowerCase();
  if (attackType.includes('normal') || attackType.includes('safe baseline')) return false;
  const severity = (item.severity || item.explanation?.severity || '').toUpperCase();
  if (severity === 'SAFE') return false;
  return true;
};

const loadLocalAnomalies = () => {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed)) {
        return parsed.filter(isGenuineAttack);
      }
    }
  } catch (e) {
    console.error("Failed to load anomalies from localStorage", e);
  }
  return [];
};

export function useThreatWebSocket() {
  const [dataHistory, setDataHistory] = useState([]);
  const [anomalyHistory, setAnomalyHistory] = useState(loadLocalAnomalies);
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
  const anomalyHistoryRef = useRef(loadLocalAnomalies());
  const metricsRef = useRef({
    totalTraffic: 0,
    detectedAnomalies: 0,
    sumScore: 0,
    latestAnomalyType: null
  });

  // Fetch persistent historical anomalies from the backend on initial load
  useEffect(() => {
    let isMounted = true;
    const fetchBackendAnomalies = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/v1/anomalies?limit=1000`);
        if (res.ok && isMounted) {
          const json = await res.json();
          const backendItems = json.data || (Array.isArray(json) ? json : []);
          if (backendItems.length > 0) {
            const validAttacks = backendItems
              .filter(isGenuineAttack)
              .map(item => {
                const itemCopy = { ...item };
                if (!itemCopy.metrics) itemCopy.metrics = {};
                if (itemCopy.metrics.timestamp && itemCopy.metrics.timestamp > 2000000000) {
                  itemCopy.metrics.timestamp = itemCopy.metrics.timestamp / 1000;
                }
                if (!itemCopy.id) {
                  itemCopy.id = `anom-${itemCopy.metrics.timestamp || Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
                }
                return itemCopy;
              });

            // Merge with local ref, avoiding duplicates by id
            const existingIds = new Set(anomalyHistoryRef.current.map(a => a.id));
            const toAdd = validAttacks.filter(a => !existingIds.has(a.id));
            if (toAdd.length > 0) {
              const merged = [...anomalyHistoryRef.current, ...toAdd]
                .filter(isGenuineAttack)
                .slice(-MAX_ANOMALY_HISTORY);
              anomalyHistoryRef.current = merged;
              setAnomalyHistory(merged);
              try {
                localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
              } catch (e) {}
            }
          }
        }
      } catch (err) {
        console.warn("Could not fetch backend anomaly history", err);
      }
    };
    fetchBackendAnomalies();
    return () => { isMounted = false; };
  }, []);

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
          
          if (!payload.metrics) {
            payload.metrics = {};
          }
          if (!payload.metrics.timestamp) {
            payload.metrics.timestamp = Date.now() / 1000;
          } else if (payload.metrics.timestamp > 2000000000) {
            payload.metrics.timestamp = payload.metrics.timestamp / 1000;
          }
          
          const newEntry = {
            ...payload,
            id: payload.id || `${payload.metrics.timestamp}-${Math.random().toString(36).substr(2, 9)}`
          };

          // Update transient sliding window (live stream)
          historyRef.current = [...historyRef.current, newEntry].slice(-MAX_HISTORY);
          
          metricsRef.current.totalTraffic += 1;
          
          // Strict check: ONLY genuine attacks enter anomaly history
          const isAttack = isGenuineAttack(newEntry);
          if (isAttack) {
            metricsRef.current.detectedAnomalies += 1;
            metricsRef.current.latestAnomalyType = newEntry.attack_type || 'Threat Detected';

            const exists = anomalyHistoryRef.current.some(a => a.id === newEntry.id);
            if (!exists) {
              const updatedAnomalies = [...anomalyHistoryRef.current, newEntry]
                .filter(isGenuineAttack)
                .slice(-MAX_ANOMALY_HISTORY);
              anomalyHistoryRef.current = updatedAnomalies;
              setAnomalyHistory(updatedAnomalies);
              try {
                localStorage.setItem(STORAGE_KEY, JSON.stringify(updatedAnomalies));
              } catch (e) {}
            }
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

  const clearAnomalyHistory = useCallback(async () => {
    anomalyHistoryRef.current = [];
    setAnomalyHistory([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (e) {}
    try {
      await fetch(`${API_BASE_URL}/api/v1/anomalies`, { method: 'DELETE' });
    } catch (err) {
      console.warn("Could not clear backend anomalies", err);
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

  return {
    dataHistory,
    anomalyHistory,
    clearAnomalyHistory,
    metrics,
    connectionStatus
  };
}
