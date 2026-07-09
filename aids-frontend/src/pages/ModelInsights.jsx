import React from 'react';
import { Database, Cpu, ActivitySquare, BrainCircuit, BarChart3, Layers } from 'lucide-react';

export default function ModelInsights() {
  return (
    <div style={{ paddingBottom: '40px' }}>
      <div className="dashboard-header" style={{ marginBottom: '24px' }}>
        <div className="dashboard-title">
          <h1>Model Insights</h1>
          <p>UNSW_NB15 Anomaly Detection Architecture (Champion Model: XGBoost)</p>
        </div>
      </div>

      <div className="insights-top-grid">
        <div className="metric-card">
          <div className="metric-header">
            <BrainCircuit size={18} className="metric-icon" />
            <span>Algorithm</span>
          </div>
          <div className="metric-value">XGBClassifier</div>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '8px' }}>Optimized using LogLoss evaluation metric.</p>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <Database size={18} className="metric-icon" />
            <span>Training Dataset</span>
          </div>
          <div className="metric-value">UNSW_NB15</div>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '8px' }}>Preprocessed via MinMaxScaler.</p>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <Layers size={18} className="metric-icon" />
            <span>Feature Space</span>
          </div>
          <div className="metric-value">5 Dimensions</div>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '8px' }}>proto, length, is_tcp, is_udp, is_icmp</p>
        </div>
      </div>

      <div className="insights-bottom-grid">
        {/* Model Pipeline */}
        <div className="chart-container" style={{ height: 'auto', padding: '32px' }}>
           <h3 style={{ marginBottom: '24px', fontSize: '1.2rem', color: '#e2e8f0' }}>Pipeline Architecture</h3>
           
           <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ padding: '16px', backgroundColor: 'rgba(59,130,246,0.1)', border: '1px solid #3b82f6', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '16px' }}>
                <Cpu size={24} color="#3b82f6" />
                <div>
                  <h4 style={{ margin: '0 0 4px 0' }}>1. Feature Extraction</h4>
                  <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>Ingesting raw pcap metrics and transforming protocol strings to numerical mapping.</p>
                </div>
              </div>

              <div style={{ width: '2px', height: '20px', backgroundColor: '#3b82f6', margin: '0 0 0 28px' }}></div>

              <div style={{ padding: '16px', backgroundColor: 'rgba(59,130,246,0.1)', border: '1px solid #3b82f6', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '16px' }}>
                <ActivitySquare size={24} color="#3b82f6" />
                <div>
                  <h4 style={{ margin: '0 0 4px 0' }}>2. Scaling (MinMaxScaler)</h4>
                  <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>Normalizing numerical feature bounds between 0 and 1.</p>
                </div>
              </div>

              <div style={{ width: '2px', height: '20px', backgroundColor: '#3b82f6', margin: '0 0 0 28px' }}></div>

              <div style={{ padding: '16px', backgroundColor: 'rgba(16,185,129,0.1)', border: '1px solid #10b981', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '16px' }}>
                <BrainCircuit size={24} color="#10b981" />
                <div>
                  <h4 style={{ margin: '0 0 4px 0' }}>3. Inference (XGBoost)</h4>
                  <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>Ensemble tree evaluation returning anomaly probability scores.</p>
                </div>
              </div>
           </div>
        </div>

        {/* Model Evaluation Metrics */}
        <div className="chart-container" style={{ height: 'auto', padding: '32px' }}>
           <h3 style={{ marginBottom: '24px', fontSize: '1.2rem', color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: '8px' }}>
             <BarChart3 size={20} /> Evaluation Matrix
           </h3>

           <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <span style={{ color: '#94a3b8' }}>ROC-AUC</span>
                  <span style={{ fontWeight: 'bold' }}>98.4%</span>
                </div>
                <div style={{ width: '100%', height: '6px', backgroundColor: '#2e2e3d', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: '98.4%', height: '100%', backgroundColor: '#10b981' }}></div>
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <span style={{ color: '#94a3b8' }}>Accuracy</span>
                  <span style={{ fontWeight: 'bold' }}>97.2%</span>
                </div>
                <div style={{ width: '100%', height: '6px', backgroundColor: '#2e2e3d', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: '97.2%', height: '100%', backgroundColor: '#3b82f6' }}></div>
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <span style={{ color: '#94a3b8' }}>F1-Score</span>
                  <span style={{ fontWeight: 'bold' }}>96.8%</span>
                </div>
                <div style={{ width: '100%', height: '6px', backgroundColor: '#2e2e3d', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: '96.8%', height: '100%', backgroundColor: '#3b82f6' }}></div>
                </div>
              </div>
           </div>

           <div style={{ marginTop: 'auto', paddingTop: '30px' }}>
             <div style={{ padding: '16px', backgroundColor: 'rgba(255,255,255,0.03)', borderRadius: '8px', border: '1px solid #2e2e3d', fontSize: '0.85rem', color: '#94a3b8' }}>
               Models Evaluated: Logistic Regression, Random Forest, Deep Neural Network (TF), XGBoost. XGBoost was exported as the champion model.
             </div>
           </div>
        </div>

      </div>
    </div>
  );
}
