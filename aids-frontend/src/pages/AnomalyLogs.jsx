import React from 'react';
import TelemetryTable from '../components/TelemetryTable';

export default function AnomalyLogs({ anomalyHistory, clearAnomalyHistory }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <TelemetryTable 
        anomalyHistory={anomalyHistory} 
        clearAnomalyHistory={clearAnomalyHistory} 
      />
    </div>
  );
}
