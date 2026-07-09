import React from 'react';
import MetricsRibbon from '../components/MetricsRibbon';
import AnomalyChart from '../components/AnomalyChart';
import TelemetryTable from '../components/TelemetryTable';

export default function Dashboard({ metrics, dataHistory }) {
  return (
    <>
      <div className="dashboard-header">
        <div className="dashboard-title">
          <h1>Threat Analysis Dashboard</h1>
          <p>Real-time anomaly detection and network telemetry</p>
        </div>
      </div>

      <MetricsRibbon metrics={metrics} />
      <div className="dashboard-main-grid">
        <AnomalyChart dataHistory={dataHistory} />
        <TelemetryTable dataHistory={dataHistory} />
      </div>
    </>
  );
}
