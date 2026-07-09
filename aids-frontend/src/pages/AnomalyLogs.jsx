import React from 'react';
import TelemetryTable from '../components/TelemetryTable';

export default function AnomalyLogs({ dataHistory }) {
  return (
    <>
      <div className="dashboard-header" style={{ marginBottom: '16px' }}>
        <div className="dashboard-title">
          <h1>Anomaly Logs</h1>
          <p>Detailed historical telemetry and alert stream</p>
        </div>
      </div>
      
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <TelemetryTable dataHistory={dataHistory} />
      </div>
    </>
  );
}
