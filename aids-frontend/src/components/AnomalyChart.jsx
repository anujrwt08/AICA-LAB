import React from 'react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  ReferenceLine
} from 'recharts';

const AnomalyChart = React.memo(({ dataHistory }) => {
  // Format data for chart
  const chartData = dataHistory.map(entry => ({
    time: entry.metrics?.timestamp ? new Date(entry.metrics.timestamp * 1000).toLocaleTimeString() : '',
    score: entry.score || 0,
    isAnomaly: entry.anomaly
  }));

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const isAnomaly = payload[0].payload.isAnomaly;
      return (
        <div style={{
          backgroundColor: 'rgba(26, 26, 36, 0.95)',
          border: `1px solid ${isAnomaly ? '#ef4444' : '#3b82f6'}`,
          padding: '12px 16px',
          borderRadius: '8px',
          boxShadow: isAnomaly ? '0 0 15px rgba(239, 68, 68, 0.4)' : '0 0 15px rgba(59, 130, 246, 0.2)',
          backdropFilter: 'blur(4px)'
        }}>
          <p style={{ margin: '0 0 8px 0', color: '#94a3b8', fontSize: '0.85rem' }}>{label}</p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: isAnomaly ? '#ef4444' : '#3b82f6' }} />
            <p style={{ margin: 0, color: '#e2e8f0', fontWeight: 600, fontSize: '1.1rem' }}>
              Loss: {payload[0].value.toFixed(2)}
            </p>
          </div>
          {isAnomaly && (
            <p style={{ margin: '8px 0 0 0', color: '#ef4444', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>
              CRITICAL ANOMALY
            </p>
          )}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="chart-container" style={{ position: 'relative' }}>
      <div className="chart-header">
        <div className="chart-title">Model Reconstruction Loss (Real-time)</div>
      </div>
      <div className="chart-body">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={chartData}
            margin={{ top: 20, right: 30, left: 0, bottom: 0 }}
          >
            <defs>
              <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4}/>
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0}/>
              </linearGradient>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="4" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#2e2e3d" vertical={false} opacity={0.5} />
            <XAxis 
              dataKey="time" 
              stroke="#64748b"
              tick={{ fill: '#64748b', fontSize: 11 }}
              tickMargin={12}
              minTickGap={40}
              axisLine={false}
              tickLine={false}
            />
            <YAxis 
              stroke="#64748b" 
              tick={{ fill: '#64748b', fontSize: 11 }}
              domain={[0, 'dataMax + 100']} 
              tickMargin={12}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ stroke: '#475569', strokeWidth: 1, strokeDasharray: '5 5' }} />
            
            <ReferenceLine 
              y={500.0} 
              stroke="#ef4444" 
              strokeWidth={1} 
              strokeDasharray="4 4" 
              label={{ position: 'insideTopLeft', value: 'THRESHOLD (500)', fill: '#ef4444', fontSize: 11, fontWeight: 600, opacity: 0.8 }} 
            />
            
            <Area 
              type="monotone" 
              dataKey="score" 
              stroke="#3b82f6" 
              strokeWidth={3}
              fillOpacity={1} 
              fill="url(#colorScore)"
              isAnimationActive={true}
              animationDuration={800}
              animationEasing="ease-out"
              filter="url(#glow)"
              dot={(props) => {
                const { cx, cy, payload } = props;
                if (payload.isAnomaly) {
                  return (
                    <circle 
                      cx={cx} 
                      cy={cy} 
                      r={5} 
                      fill="#ef4444" 
                      stroke="#1a1a24" 
                      strokeWidth={2} 
                      key={`dot-${cx}-${cy}`}
                      style={{ filter: 'drop-shadow(0 0 6px rgba(239,68,68,0.8))' }}
                    />
                  );
                }
                return null;
              }}
              activeDot={{ r: 6, fill: '#60a5fa', stroke: '#1a1a24', strokeWidth: 2, filter: 'drop-shadow(0 0 6px rgba(96,165,250,0.8))' }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
});

export default AnomalyChart;
