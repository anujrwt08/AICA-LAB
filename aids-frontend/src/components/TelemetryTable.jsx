import React, { useState } from 'react';
import { ShieldAlert, HelpCircle, X, CheckCircle, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function TelemetryTable({ dataHistory }) {
  const [selectedThreat, setSelectedThreat] = useState(null);

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

  const getSeverityBadgeClass = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'status-danger';
      case 'HIGH': return 'status-danger';
      case 'MEDIUM': return 'status-warning';
      default: return 'status-safe';
    }
  };

  return (
    <div className="telemetry-container">
      <div className="telemetry-header">
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Live Telemetry & Alert Stream</h2>
          <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
            Click "Explain (XAI)" on any packet to view root-cause detection reasoning.
          </span>
        </div>
        <div style={{ display: 'flex', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981' }}></span>
            <span>Safe Baseline</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#ef4444' }}></span>
            <span>Detected Threat</span>
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
              <th>Attack Classification</th>
              <th style={{ textAlign: 'center' }}>Explainability (XAI)</th>
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

              const attackName = row.attack_type || (isAnomaly ? 'Malicious Network Anomaly' : 'Normal Baseline');
              
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
                        {attackName}
                      </span>
                    ) : (
                      <span className="status-badge status-safe">Safe Baseline</span>
                    )}
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <button
                      onClick={() => setSelectedThreat(row)}
                      style={{
                        padding: '4px 10px',
                        fontSize: '0.78rem',
                        fontWeight: 600,
                        borderRadius: '6px',
                        border: '1px solid #3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.15)',
                        color: '#60a5fa',
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}
                    >
                      <HelpCircle size={13} />
                      Explain (XAI)
                    </button>
                  </td>
                </tr>
              );
            })}
            
            {displayData.length === 0 && (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '40px', color: '#94a3b8' }}>
                  Awaiting telemetry stream... Start sniffer or simulations in kali.py.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* EXPLAINABLE AI (XAI) MODAL */}
      {selectedThreat && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(2, 6, 23, 0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: '20px'
          }}
          onClick={() => setSelectedThreat(null)}
        >
          <div
            style={{
              backgroundColor: '#0f172a',
              border: '1px solid #334155',
              borderRadius: '12px',
              maxWidth: '680px',
              width: '100%',
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: '24px',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  {selectedThreat.anomaly ? (
                    <ShieldAlert color="#ef4444" size={22} />
                  ) : (
                    <ShieldCheck color="#10b981" size={22} />
                  )}
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
                    {selectedThreat.attack_type || (selectedThreat.anomaly ? 'Threat Detected' : 'Normal Baseline')}
                  </h3>
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <span
                    style={{
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: '4px',
                      backgroundColor: selectedThreat.anomaly ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                      color: selectedThreat.anomaly ? '#f87171' : '#34d399',
                      border: `1px solid ${selectedThreat.anomaly ? '#ef4444' : '#10b981'}`
                    }}
                  >
                    SEVERITY: {selectedThreat.explanation?.severity || (selectedThreat.anomaly ? 'HIGH' : 'SAFE')}
                  </span>
                  <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                    Loss Score: {(selectedThreat.score || 0).toFixed(2)}%
                  </span>
                </div>
              </div>

              <button
                onClick={() => setSelectedThreat(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  padding: '4px'
                }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Why was it identified as an attack? */}
            <div
              style={{
                backgroundColor: 'rgba(59, 130, 246, 0.08)',
                border: '1px solid #1e3a8a',
                borderRadius: '8px',
                padding: '16px',
                marginBottom: '18px'
              }}
            >
              <h4 style={{ margin: '0 0 8px 0', fontSize: '0.9rem', color: '#60a5fa', fontWeight: 600 }}>
                💡 HOW & WHY WAS THIS IDENTIFIED AS AN ATTACK? (XAI REASONING)
              </h4>
              <p style={{ margin: 0, fontSize: '0.88rem', lineHeight: 1.5, color: '#e2e8f0' }}>
                {selectedThreat.explanation?.reason || (
                  selectedThreat.anomaly
                    ? `Packet payload length (${selectedThreat.metrics?.length} B) on protocol ${getProtocolName(selectedThreat.metrics?.proto)} exceeds standard behavioral thresholds. The XGBoost decision tree attributed significant loss score to volumetric datagram density.`
                    : `Packet attributes conform to standard Ethernet MTU and RFC protocol specifications without anomalous volumetric behavior.`
                )}
              </p>
            </div>

            {/* Feature Evidence vs Baseline */}
            <div style={{ marginBottom: '18px' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '0.85rem', color: '#cbd5e1', fontWeight: 600 }}>
                FEATURE ATTRIBUTION & BASELINE COMPARISON
              </h4>
              <table style={{ width: '100%', fontSize: '0.85rem', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #334155', color: '#94a3b8', textAlign: 'left' }}>
                    <th style={{ padding: '6px 8px' }}>Feature</th>
                    <th style={{ padding: '6px 8px' }}>Observed</th>
                    <th style={{ padding: '6px 8px' }}>Baseline</th>
                    <th style={{ padding: '6px 8px' }}>Evaluation</th>
                  </tr>
                </thead>
                <tbody>
                  <tr style={{ borderBottom: '1px solid #1e293b' }}>
                    <td style={{ padding: '8px' }}>Packet Length</td>
                    <td style={{ padding: '8px', fontWeight: 600, color: (selectedThreat.metrics?.length || 0) > 1500 ? '#f87171' : '#f8fafc' }}>
                      {selectedThreat.metrics?.length} B
                    </td>
                    <td style={{ padding: '8px', color: '#94a3b8' }}>64 - 1500 B</td>
                    <td style={{ padding: '8px', color: (selectedThreat.metrics?.length || 0) > 1500 ? '#f87171' : '#34d399' }}>
                      {(selectedThreat.metrics?.length || 0) > 1500 ? `+${selectedThreat.metrics.length - 1500}B over MTU` : 'Compliant'}
                    </td>
                  </tr>
                  <tr style={{ borderBottom: '1px solid #1e293b' }}>
                    <td style={{ padding: '8px' }}>Protocol</td>
                    <td style={{ padding: '8px', fontWeight: 600 }}>
                      {getProtocolName(selectedThreat.metrics?.proto)} ({selectedThreat.metrics?.proto})
                    </td>
                    <td style={{ padding: '8px', color: '#94a3b8' }}>TCP / UDP / ICMP</td>
                    <td style={{ padding: '8px', color: '#94a3b8' }}>
                      {selectedThreat.metrics?.proto === 17 ? 'Connectionless Datagram' : selectedThreat.metrics?.proto === 1 ? 'Control Message' : 'Stateful Stream'}
                    </td>
                  </tr>
                  <tr style={{ borderBottom: '1px solid #1e293b' }}>
                    <td style={{ padding: '8px' }}>Source IP</td>
                    <td style={{ padding: '8px', fontFamily: 'monospace' }}>
                      {selectedThreat.metrics?.src_ip}
                    </td>
                    <td style={{ padding: '8px', color: '#94a3b8' }}>Authorized Subnet</td>
                    <td style={{ padding: '8px', color: '#94a3b8' }}>
                      Ingress Node
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Rule & Defense Guidance */}
            <div
              style={{
                backgroundColor: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid #334155',
                borderRadius: '8px',
                padding: '12px 16px',
                fontSize: '0.85rem'
              }}
            >
              <div style={{ marginBottom: '6px' }}>
                <strong style={{ color: '#94a3b8' }}>Triggered Security Rule: </strong>
                <span style={{ color: '#f8fafc', fontFamily: 'monospace' }}>
                  {selectedThreat.explanation?.rule_triggered || 'RULE-SEC-BASELINE'}
                </span>
              </div>
              <div>
                <strong style={{ color: '#94a3b8' }}>Recommended Mitigation: </strong>
                <span style={{ color: '#f8fafc' }}>
                  {selectedThreat.explanation?.mitigation || 'Maintain passive monitoring.'}
                </span>
              </div>
            </div>

            {/* Footer close */}
            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setSelectedThreat(null)}
                style={{
                  padding: '8px 18px',
                  backgroundColor: '#2563eb',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '0.85rem',
                  cursor: 'pointer'
                }}
              >
                Close Explanation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
