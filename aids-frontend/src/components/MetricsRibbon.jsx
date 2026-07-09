import React from 'react';
import { Activity, AlertTriangle, Target, ActivitySquare } from 'lucide-react';

export default function MetricsRibbon({ metrics }) {
  const { totalTraffic, detectedAnomalies, currentThreshold, averageErrorScore } = metrics;
  
  const hasAnomalies = detectedAnomalies > 0;

  return (
    <div className="metrics-ribbon">
      <div className="metric-card">
        <div className="metric-header">
          <Activity size={18} className="metric-icon" />
          <span>Total Inspected Traffic</span>
        </div>
        <div className="metric-value">
          {totalTraffic.toLocaleString()}
        </div>
      </div>
      
      <div className={`metric-card ${hasAnomalies ? 'alert' : ''}`}>
        <div className="metric-header">
          <AlertTriangle size={18} className="metric-icon" />
          <span>Detected Anomalies</span>
        </div>
        <div className="metric-value">
          {detectedAnomalies.toLocaleString()}
        </div>
        {hasAnomalies && metrics.latestAnomalyType && (
          <div style={{ fontSize: '0.8rem', color: 'var(--danger-color)', marginTop: '-4px', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Latest: {metrics.latestAnomalyType}
          </div>
        )}
      </div>
      
      <div className="metric-card">
        <div className="metric-header">
          <Target size={18} className="metric-icon" />
          <span>Current Sensitivity Threshold</span>
        </div>
        <div className="metric-value">
          {currentThreshold.toFixed(1)}
        </div>
      </div>
      
      <div className="metric-card">
        <div className="metric-header">
          <ActivitySquare size={18} className="metric-icon" />
          <span>Average Model Error Score</span>
        </div>
        <div className="metric-value">
          {averageErrorScore.toFixed(2)}
        </div>
      </div>
    </div>
  );
}
