import React from 'react';

export default function TelemetryTable({ dataHistory }) {
  // Reverse to show latest first
  const displayData = [...dataHistory].reverse();

  const getProtocolName = (proto) => {
    switch (proto) {
      case 6: return 'TCP';
      case 17: return 'UDP';
      case 1: return 'ICMP';
      default: return `PROTO-${proto}`;
    }
  };

  return (
    <div className="telemetry-container">
      <div className="telemetry-header">
        <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Live Telemetry & Alert Stream</h2>
        <div style={{ display: 'flex', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981' }}></span>
            <span>Safe</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#ef4444' }}></span>
            <span>Anomaly</span>
          </div>
        </div>
      </div>
      <div className="table-wrapper">
        <table className="log-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Protocol</th>
              <th>Packet Length</th>
              <th>Loss Score</th>
              <th>Security Status</th>
            </tr>
          </thead>
          <tbody>
            {displayData.map((row) => {
              const isAnomaly = row.anomaly;
              const date = new Date((row.metrics?.timestamp || 0) * 1000);
              const timeString = isNaN(date.getTime()) ? '-' : date.toLocaleString('en-IN', { 
                timeZone: 'Asia/Kolkata',
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: true
              });
              
              return (
                <tr key={row.id} className={isAnomaly ? 'log-row-alert' : ''}>
                  <td style={{ color: '#94a3b8' }}>{timeString}</td>
                  <td style={{ fontFamily: 'monospace' }}>{row.metrics?.src_ip || '-'}</td>
                  <td style={{ fontFamily: 'monospace' }}>{row.metrics?.dst_ip || '-'}</td>
                  <td>{row.metrics?.proto !== undefined ? getProtocolName(row.metrics.proto) : '-'}</td>
                  <td>{row.metrics?.length !== undefined ? row.metrics.length.toLocaleString() + ' B' : '-'}</td>
                  <td style={{ color: isAnomaly ? '#ef4444' : '#e2e8f0', fontWeight: isAnomaly ? 600 : 400 }}>
                    {row.score ? row.score.toFixed(2) : '-'}
                  </td>
                  <td>
                    {isAnomaly ? (
                      <span className="status-badge status-danger">
                        {row.attack_type || 'Threat Detected'}
                      </span>
                    ) : (
                      <span className="status-badge status-safe">Safe</span>
                    )}
                  </td>
                </tr>
              );
            })}
            
            {displayData.length === 0 && (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '40px', color: '#94a3b8' }}>
                  Awaiting telemetry stream...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
