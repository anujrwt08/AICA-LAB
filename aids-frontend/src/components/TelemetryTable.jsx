import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, 
  HelpCircle, 
  X, 
  ShieldCheck, 
  Download, 
  Trash2, 
  Search, 
  Filter, 
  FileSpreadsheet, 
  FileCode, 
  RefreshCw,
  AlertTriangle,
  ArrowRight
} from 'lucide-react';

// Strict filter to guarantee ONLY real attacks are shown in Anomaly Logs (no safe baseline traffic)
const isGenuineAttack = (item) => {
  if (!item || item.anomaly !== true) return false;
  const attackType = (item.attack_type || '').toLowerCase();
  if (attackType.includes('normal') || attackType.includes('safe baseline')) return false;
  const severity = (item.severity || item.explanation?.severity || '').toUpperCase();
  if (severity === 'SAFE') return false;
  return true;
};

export default function TelemetryTable({ anomalyHistory = [], clearAnomalyHistory }) {
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAttackType, setSelectedAttackType] = useState('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [sortBy, setSortBy] = useState('newest');
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  // Filter strictly to attacks only
  const attacksOnly = useMemo(() => {
    return (anomalyHistory || []).filter(isGenuineAttack);
  }, [anomalyHistory]);

  // Protocol mapper helper
  const getProtocolName = (proto) => {
    switch (proto) {
      case 6: return 'TCP';
      case 17: return 'UDP';
      case 1: return 'ICMP';
      default: return `PROTO-${proto}`;
    }
  };

  // Protocol badge color styling
  const getProtocolBadgeStyle = (proto) => {
    switch (proto) {
      case 6:
        return { backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.3)' };
      case 17:
        return { backgroundColor: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', border: '1px solid rgba(168, 85, 247, 0.3)' };
      case 1:
        return { backgroundColor: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.3)' };
      default:
        return { backgroundColor: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8', border: '1px solid rgba(148, 163, 184, 0.3)' };
    }
  };

  // Severity badge component
  const renderSeverityBadge = (severity) => {
    const sev = (severity || 'HIGH').toUpperCase();
    if (sev === 'CRITICAL') {
      return (
        <span 
          style={{ 
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            padding: '3px 9px',
            borderRadius: '12px',
            fontSize: '0.72rem',
            fontWeight: 700,
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            color: '#f87171',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            letterSpacing: '0.5px'
          }}
        >
          <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: '#ef4444' }}></span>
          CRITICAL
        </span>
      );
    }
    if (sev === 'HIGH') {
      return (
        <span 
          style={{ 
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            padding: '3px 9px',
            borderRadius: '12px',
            fontSize: '0.72rem',
            fontWeight: 700,
            backgroundColor: 'rgba(245, 158, 11, 0.15)',
            color: '#fbbf24',
            border: '1px solid rgba(245, 158, 11, 0.35)',
            letterSpacing: '0.5px'
          }}
        >
          <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: '#f59e0b' }}></span>
          HIGH
        </span>
      );
    }
    return (
      <span 
        style={{ 
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          padding: '3px 9px',
          borderRadius: '12px',
          fontSize: '0.72rem',
          fontWeight: 700,
          backgroundColor: 'rgba(234, 179, 8, 0.12)',
          color: '#facc15',
          border: '1px solid rgba(234, 179, 8, 0.25)',
          letterSpacing: '0.5px'
        }}
      >
        <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: '#eab308' }}></span>
        MEDIUM
      </span>
    );
  };

  // Distinct attack types present in recorded attack history
  const availableAttackTypes = useMemo(() => {
    const types = new Set();
    attacksOnly.forEach(item => {
      if (item.attack_type) types.add(item.attack_type);
    });
    return Array.from(types);
  }, [attacksOnly]);

  // Overall statistics for the slim metric bar
  const stats = useMemo(() => {
    const totalThreats = attacksOnly.length;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let totalScore = 0;

    attacksOnly.forEach(item => {
      const sev = (item.severity || item.explanation?.severity || 'HIGH').toUpperCase();
      if (sev === 'CRITICAL') criticalCount++;
      else if (sev === 'HIGH') highCount++;
      else if (sev === 'MEDIUM') mediumCount++;
      totalScore += (item.score || 0);
    });

    const avgScore = totalThreats > 0 ? (totalScore / totalThreats).toFixed(1) : '0.0';
    const latestThreat = attacksOnly.length > 0 ? attacksOnly[attacksOnly.length - 1] : null;

    return {
      totalThreats,
      criticalCount,
      highCount,
      mediumCount,
      avgScore,
      latestThreat
    };
  }, [attacksOnly]);

  // Filtered and sorted data for the table
  const displayData = useMemo(() => {
    let result = [...attacksOnly];

    // Filter by search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter(item => {
        const src = (item.metrics?.src_ip || '').toLowerCase();
        const dst = (item.metrics?.dst_ip || '').toLowerCase();
        const attack = (item.attack_type || '').toLowerCase();
        const rule = (item.explanation?.rule_triggered || '').toLowerCase();
        const proto = getProtocolName(item.metrics?.proto).toLowerCase();
        return src.includes(q) || dst.includes(q) || attack.includes(q) || rule.includes(q) || proto.includes(q);
      });
    }

    // Filter by attack type
    if (selectedAttackType !== 'ALL') {
      result = result.filter(item => item.attack_type === selectedAttackType);
    }

    // Filter by severity
    if (selectedSeverity !== 'ALL') {
      result = result.filter(item => {
        const sev = (item.severity || item.explanation?.severity || 'HIGH').toUpperCase();
        return sev === selectedSeverity;
      });
    }

    // Sort order
    if (sortBy === 'newest') {
      result.sort((a, b) => (b.metrics?.timestamp || 0) - (a.metrics?.timestamp || 0));
    } else if (sortBy === 'oldest') {
      result.sort((a, b) => (a.metrics?.timestamp || 0) - (b.metrics?.timestamp || 0));
    } else if (sortBy === 'score-desc') {
      result.sort((a, b) => (b.score || 0) - (a.score || 0));
    } else if (sortBy === 'score-asc') {
      result.sort((a, b) => (a.score || 0) - (b.score || 0));
    }

    return result;
  }, [attacksOnly, searchQuery, selectedAttackType, selectedSeverity, sortBy]);

  // Export to CSV
  const handleExportCsv = () => {
    const itemsToExport = displayData.length > 0 ? displayData : attacksOnly;
    if (!itemsToExport || itemsToExport.length === 0) {
      alert("No attack logs available to export.");
      return;
    }

    const headers = [
      "Incident ID",
      "Timestamp (Formatted)",
      "Unix Timestamp (s)",
      "Source IP",
      "Destination IP",
      "Protocol",
      "Packet Length (Bytes)",
      "Loss Score (%)",
      "Attack Classification",
      "Severity",
      "Triggered Rule",
      "Dominant Feature",
      "XAI Root Cause Reason",
      "Mitigation Guidance"
    ];

    const escapeCsv = (val) => {
      if (val === undefined || val === null) return '""';
      const str = String(val).replace(/"/g, '""');
      return `"${str}"`;
    };

    const rows = itemsToExport.map(item => {
      const date = new Date((item.metrics?.timestamp || 0) * 1000);
      const timeStr = isNaN(date.getTime()) ? '-' : date.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
      const unixTs = item.metrics?.timestamp || '';
      const src = item.metrics?.src_ip || '-';
      const dst = item.metrics?.dst_ip || '-';
      const proto = getProtocolName(item.metrics?.proto);
      const length = item.metrics?.length !== undefined ? item.metrics.length : '-';
      const score = item.score !== undefined ? Number(item.score).toFixed(2) : '-';
      const attack = item.attack_type || 'Malicious Network Anomaly';
      const severity = item.severity || item.explanation?.severity || 'HIGH';
      const rule = item.explanation?.rule_triggered || '';
      const dominant = item.explanation?.dominant_feature || '';
      const reason = item.explanation?.reason || '';
      const mitigation = item.explanation?.mitigation || '';

      return [
        escapeCsv(item.id || ''),
        escapeCsv(timeStr),
        escapeCsv(unixTs),
        escapeCsv(src),
        escapeCsv(dst),
        escapeCsv(proto),
        escapeCsv(length),
        escapeCsv(score),
        escapeCsv(attack),
        escapeCsv(severity),
        escapeCsv(rule),
        escapeCsv(dominant),
        escapeCsv(reason),
        escapeCsv(mitigation)
      ].join(',');
    });

    const csvContent = "\uFEFF" + [headers.join(','), ...rows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const nowStr = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `threatshield_attack_logs_${nowStr}.csv`;

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Export to JSON
  const handleExportJson = () => {
    const itemsToExport = displayData.length > 0 ? displayData : attacksOnly;
    if (!itemsToExport || itemsToExport.length === 0) {
      alert("No attack logs available to export.");
      return;
    }

    const exportData = itemsToExport.map(item => {
      const date = new Date((item.metrics?.timestamp || 0) * 1000);
      return {
        id: item.id,
        timestamp_formatted: isNaN(date.getTime()) ? null : date.toISOString(),
        metrics: item.metrics,
        anomaly: item.anomaly,
        attack_type: item.attack_type,
        severity: item.severity || item.explanation?.severity || 'HIGH',
        score: item.score,
        explanation: item.explanation
      };
    });

    const jsonContent = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
    const nowStr = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `threatshield_attack_logs_${nowStr}.json`;

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleResetFilters = () => {
    setSearchQuery('');
    setSelectedAttackType('ALL');
    setSelectedSeverity('ALL');
    setSortBy('newest');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '14px' }}>
      
      {/* 1. CLEAN ENTERPRISE PAGE HEADER */}
      <div className="incident-page-header">
        <div className="incident-title-area">
          <h1>
            <span>Incident & Anomaly Logs</span>
            <span className="threat-count-pill">
              <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: '#ef4444' }}></span>
              {stats.totalThreats} {stats.totalThreats === 1 ? 'Attack Logged' : 'Attacks Logged'}
            </span>
          </h1>
          <p>Forensic history of detected threats, root-cause Explainable AI (XAI), and log export</p>
        </div>

        {/* Action Buttons: Export CSV, Export JSON, Clear */}
        <div className="incident-actions-group">
          <button
            onClick={handleExportCsv}
            title="Download complete attack history as CSV for Excel analysis"
            className="btn-cyber btn-cyber-primary"
          >
            <FileSpreadsheet size={15} />
            <span>Export CSV</span>
          </button>

          <button
            onClick={handleExportJson}
            title="Download full attack telemetry as JSON"
            className="btn-cyber btn-cyber-outline"
          >
            <FileCode size={15} />
            <span>Export JSON</span>
          </button>

          {attacksOnly.length > 0 && (
            <button
              onClick={() => setShowClearConfirm(true)}
              title="Clear all recorded attack history"
              className="btn-cyber btn-cyber-danger"
            >
              <Trash2 size={14} />
              <span>Clear</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. LOW-PROFILE METRIC STRIP (Single clean horizontal bar) */}
      <div className="incident-metric-strip">
        <div className="incident-metric-item">
          <span className="metric-label">Total Incidents:</span>
          <span className="metric-value-clean">{stats.totalThreats}</span>
        </div>

        <div className="metric-divider"></div>

        <div className="incident-metric-item">
          <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: '#ef4444', display: 'inline-block' }}></span>
          <span className="metric-label">Critical:</span>
          <span className="metric-value-clean" style={{ color: '#f87171' }}>{stats.criticalCount}</span>
        </div>

        <div className="metric-divider"></div>

        <div className="incident-metric-item">
          <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: '#f59e0b', display: 'inline-block' }}></span>
          <span className="metric-label">High:</span>
          <span className="metric-value-clean" style={{ color: '#fbbf24' }}>{stats.highCount}</span>
        </div>

        <div className="metric-divider"></div>

        <div className="incident-metric-item">
          <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: '#eab308', display: 'inline-block' }}></span>
          <span className="metric-label">Medium:</span>
          <span className="metric-value-clean" style={{ color: '#facc15' }}>{stats.mediumCount}</span>
        </div>

        <div className="metric-divider"></div>

        <div className="incident-metric-item">
          <span className="metric-label">Avg Threat Score:</span>
          <span className="metric-value-clean" style={{ color: '#38bdf8' }}>{stats.avgScore}%</span>
        </div>

        {stats.latestThreat && (
          <>
            <div className="metric-divider"></div>
            <div className="incident-metric-item" style={{ maxWidth: '320px', overflow: 'hidden' }}>
              <span className="metric-label">Latest:</span>
              <span className="metric-value-clean" style={{ color: '#cbd5e1', fontSize: '0.85rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {stats.latestThreat.attack_type}
              </span>
            </div>
          </>
        )}
      </div>

      {/* 3. MAIN TABLE CONTAINER */}
      <div className="telemetry-container" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        
        {/* Streamlined Filter Toolbar */}
        <div className="incident-filter-bar">
          <div className="clean-search-wrap">
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
            <input
              type="text"
              className="clean-search-input"
              placeholder="Search by IP, attack name, protocol, or rule..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <X 
                size={14} 
                onClick={() => setSearchQuery('')}
                style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', color: '#94a3b8', cursor: 'pointer' }} 
              />
            )}
          </div>

          {/* Filter by Attack Type */}
          <select
            className="clean-select"
            value={selectedAttackType}
            onChange={(e) => setSelectedAttackType(e.target.value)}
          >
            <option value="ALL">All Attack Types</option>
            {availableAttackTypes.map(type => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>

          {/* Filter by Severity */}
          <select
            className="clean-select"
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
          </select>

          {/* Sort */}
          <select
            className="clean-select"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="score-desc">Highest Score</option>
            <option value="score-asc">Lowest Score</option>
          </select>

          {/* Reset button */}
          {(searchQuery || selectedAttackType !== 'ALL' || selectedSeverity !== 'ALL' || sortBy !== 'newest') && (
            <button
              onClick={handleResetFilters}
              style={{
                padding: '6px 10px',
                fontSize: '0.78rem',
                borderRadius: '6px',
                border: '1px solid #334155',
                backgroundColor: 'transparent',
                color: '#94a3b8',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
            >
              <RefreshCw size={12} />
              Reset
            </button>
          )}

          {/* Counter info */}
          <div style={{ marginLeft: 'auto', fontSize: '0.78rem', color: '#64748b' }}>
            Showing <strong>{displayData.length}</strong> of <strong>{attacksOnly.length}</strong> recorded attacks
          </div>
        </div>

        {/* 4. THE INCIDENT LOG TABLE */}
        <div className="table-wrapper">
          <table className="log-table">
            <thead>
              <tr>
                <th style={{ width: '130px' }}>Timestamp</th>
                <th>Attack Classification</th>
                <th style={{ width: '110px' }}>Severity</th>
                <th>Network Flow (Src ➔ Dst)</th>
                <th style={{ width: '130px' }}>Protocol & Payload</th>
                <th style={{ width: '90px' }}>Loss Score</th>
                <th style={{ width: '120px', textAlign: 'center' }}>Forensics</th>
              </tr>
            </thead>
            <tbody>
              {displayData.map((row) => {
                const date = new Date((row.metrics?.timestamp || 0) * 1000);
                const timeString = isNaN(date.getTime()) ? '-' : date.toLocaleTimeString('en-IN', {
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                  hour12: true
                });
                const dateString = isNaN(date.getTime()) ? '' : date.toLocaleDateString('en-IN', {
                  day: '2-digit',
                  month: 'short',
                  year: 'numeric'
                });

                const attackName = row.attack_type || 'Malicious Network Anomaly';
                const severityVal = row.severity || row.explanation?.severity || 'HIGH';
                const rule = row.explanation?.rule_triggered || 'RULE-XAI-ATTACK';

                return (
                  <tr key={row.id} style={{ borderBottom: '1px solid #1a2234' }}>
                    {/* Timestamp */}
                    <td>
                      <div style={{ fontFamily: 'monospace', fontWeight: 600, color: '#f8fafc', fontSize: '0.84rem' }}>
                        {timeString}
                      </div>
                      <div style={{ fontSize: '0.72rem', color: '#64748b' }}>
                        {dateString}
                      </div>
                    </td>

                    {/* Attack Classification */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <ShieldAlert size={16} color="#ef4444" style={{ flexShrink: 0 }} />
                        <div>
                          <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.88rem' }}>
                            {attackName}
                          </div>
                          <div style={{ fontSize: '0.72rem', color: '#64748b', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '280px' }}>
                            {rule}
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Severity */}
                    <td>
                      {renderSeverityBadge(severityVal)}
                    </td>

                    {/* Network Flow (Src ➔ Dst) */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', whiteSpace: 'nowrap' }}>
                        <span className="flow-node">{row.metrics?.src_ip || '-'}</span>
                        <span className="flow-arrow">➔</span>
                        <span className="flow-node" style={{ color: '#94a3b8' }}>{row.metrics?.dst_ip || '-'}</span>
                      </div>
                    </td>

                    {/* Protocol & Payload */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span 
                          style={{ 
                            padding: '2px 6px', 
                            borderRadius: '4px', 
                            fontSize: '0.72rem', 
                            fontWeight: 700,
                            ...getProtocolBadgeStyle(row.metrics?.proto)
                          }}
                        >
                          {row.metrics?.proto !== undefined ? getProtocolName(row.metrics.proto) : '-'}
                        </span>
                        <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                          {row.metrics?.length !== undefined ? row.metrics.length.toLocaleString() + ' B' : '-'}
                        </span>
                      </div>
                    </td>

                    {/* Loss Score */}
                    <td>
                      <span style={{ color: '#ef4444', fontWeight: 700, fontSize: '0.85rem' }}>
                        {row.score ? row.score.toFixed(1) + '%' : '-'}
                      </span>
                    </td>

                    {/* Action */}
                    <td style={{ textAlign: 'center' }}>
                      <button
                        onClick={() => setSelectedThreat(row)}
                        style={{
                          padding: '5px 12px',
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          borderRadius: '6px',
                          border: '1px solid #2563eb',
                          backgroundColor: 'rgba(37, 99, 235, 0.15)',
                          color: '#60a5fa',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '5px',
                          transition: 'all 0.2s ease'
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.backgroundColor = 'rgba(37, 99, 235, 0.3)';
                          e.currentTarget.style.borderColor = '#60a5fa';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.backgroundColor = 'rgba(37, 99, 235, 0.15)';
                          e.currentTarget.style.borderColor = '#2563eb';
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
                  <td colSpan="7" style={{ textAlign: 'center', padding: '60px 20px', color: '#94a3b8' }}>
                    <ShieldCheck size={40} color="#10b981" style={{ marginBottom: '12px' }} />
                    <div style={{ fontSize: '1.05rem', fontWeight: 600, color: '#f8fafc', marginBottom: '6px' }}>
                      {searchQuery || selectedAttackType !== 'ALL' || selectedSeverity !== 'ALL'
                        ? 'No recorded attacks match the active filters.'
                        : 'No Security Incidents Detected'}
                    </div>
                    <div style={{ fontSize: '0.85rem', color: '#64748b', maxWidth: '420px', margin: '0 auto', lineHeight: 1.5 }}>
                      {searchQuery || selectedAttackType !== 'ALL' || selectedSeverity !== 'ALL'
                        ? 'Try clearing your search query or selecting "All Attack Types" to see full history.'
                        : 'Your network traffic baseline is clean. When attack patterns or simulations occur in kali.py, they are recorded here permanently.'}
                    </div>
                    {(searchQuery || selectedAttackType !== 'ALL' || selectedSeverity !== 'ALL') && (
                      <button
                        onClick={handleResetFilters}
                        style={{
                          marginTop: '14px',
                          padding: '6px 16px',
                          backgroundColor: '#1e293b',
                          border: '1px solid #334155',
                          borderRadius: '6px',
                          color: '#38bdf8',
                          cursor: 'pointer',
                          fontSize: '0.82rem',
                          fontWeight: 600
                        }}
                      >
                        Reset Search Filters
                      </button>
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 5. CLEAR CONFIRMATION MODAL */}
      {showClearConfirm && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(2, 6, 23, 0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 10000,
            padding: '20px'
          }}
          onClick={() => setShowClearConfirm(false)}
        >
          <div
            style={{
              backgroundColor: '#0f172a',
              border: '1px solid #ef4444',
              borderRadius: '12px',
              maxWidth: '440px',
              width: '100%',
              padding: '22px',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#ef4444', marginBottom: '10px' }}>
              <AlertTriangle size={22} />
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc' }}>
                Clear All Attack History?
              </h3>
            </div>
            <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.5, marginBottom: '20px' }}>
              Are you sure you want to permanently clear all <strong>{attacksOnly.length}</strong> recorded attack logs?
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                onClick={() => setShowClearConfirm(false)}
                style={{
                  padding: '7px 16px',
                  backgroundColor: '#1e293b',
                  color: '#e2e8f0',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (clearAnomalyHistory) clearAnomalyHistory();
                  setShowClearConfirm(false);
                }}
                style={{
                  padding: '7px 16px',
                  backgroundColor: '#ef4444',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Yes, Clear
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 6. EXPLAINABLE AI (XAI) MODAL */}
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
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <ShieldAlert color="#ef4444" size={22} />
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
                    {selectedThreat.attack_type || 'Threat Detected'}
                  </h3>
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  {renderSeverityBadge(selectedThreat.severity || selectedThreat.explanation?.severity || 'HIGH')}
                  <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                    Loss Score: {(selectedThreat.score || 0).toFixed(2)}%
                  </span>
                  <span style={{ fontSize: '0.78rem', color: '#64748b', fontFamily: 'monospace' }}>
                    ID: {selectedThreat.id}
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
              <h4 style={{ margin: '0 0 8px 0', fontSize: '0.88rem', color: '#60a5fa', fontWeight: 600 }}>
                💡 HOW & WHY WAS THIS IDENTIFIED AS AN ATTACK? (XAI REASONING)
              </h4>
              <p style={{ margin: 0, fontSize: '0.86rem', lineHeight: 1.5, color: '#e2e8f0' }}>
                {selectedThreat.explanation?.reason || (
                  `Packet payload length (${selectedThreat.metrics?.length} B) on protocol ${getProtocolName(selectedThreat.metrics?.proto)} exceeds standard behavioral thresholds. The XGBoost decision tree attributed significant loss score to volumetric datagram density.`
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
                  {selectedThreat.explanation?.rule_triggered || 'RULE-SEC-ALERT'}
                </span>
              </div>
              <div>
                <strong style={{ color: '#94a3b8' }}>Recommended Mitigation: </strong>
                <span style={{ color: '#f8fafc' }}>
                  {selectedThreat.explanation?.mitigation || 'Maintain active inspection and firewall filtering.'}
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
