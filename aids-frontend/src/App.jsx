import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useThreatWebSocket } from './hooks/useThreatWebSocket';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import AnomalyLogs from './pages/AnomalyLogs';
import NetworkTopology from './pages/NetworkTopology';
import ModelInsights from './pages/ModelInsights';

function App() {
  const { dataHistory, metrics, connectionStatus } = useThreatWebSocket();

  return (
    <BrowserRouter>
      <div className="app-container">
        <Sidebar />
        
        <main className="main-content">
          <div className="connection-status-bar">
             <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div 
                  style={{ 
                    width: '10px', 
                    height: '10px', 
                    borderRadius: '50%', 
                    backgroundColor: connectionStatus === 'Connected' ? '#10b981' : 
                                     connectionStatus === 'Connecting' ? '#f59e0b' : '#ef4444' 
                  }}
                />
                <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 500 }}>
                  {connectionStatus === 'Connected' ? 'Live Stream Active' : 
                   connectionStatus === 'Connecting' ? 'Establishing Connection...' : 'Connection Lost'}
                </span>
              </div>
          </div>

          <div className="dashboard-workspace">
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route 
                path="/dashboard" 
                element={<Dashboard metrics={metrics} dataHistory={dataHistory} />} 
              />
              <Route 
                path="/logs" 
                element={<AnomalyLogs dataHistory={dataHistory} />} 
              />
              <Route 
                path="/topology" 
                element={<NetworkTopology dataHistory={dataHistory} />} 
              />
              <Route 
                path="/insights" 
                element={<ModelInsights />} 
              />
              <Route 
                path="*" 
                element={
                  <div style={{ textAlign: 'center', marginTop: '100px', color: '#94a3b8' }}>
                    <h2>Page under construction</h2>
                  </div>
                } 
              />
            </Routes>
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
