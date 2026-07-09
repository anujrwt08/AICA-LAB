import React, { useMemo, useRef, useEffect, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

export default function NetworkTopology({ dataHistory }) {
  const containerRef = useRef();
  const graphRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  useEffect(() => {
    if (containerRef.current) {
      const { clientWidth, clientHeight } = containerRef.current;
      setDimensions({ width: clientWidth, height: clientHeight });
    }
  }, []);

  // Apply custom physics to spread nodes out and prevent congestion!
  useEffect(() => {
    if (graphRef.current) {
      // Massively increase the repulsive force between nodes so they push away from each other
      graphRef.current.d3Force('charge').strength(-800);
      // Increase the distance of the links so the graph expands
      graphRef.current.d3Force('link').distance(150);
    }
  }, [dataHistory]); // Re-apply if data changes significantly, though once is usually enough

  // Process streaming data into graph format
  const graphData = useMemo(() => {
    const nodesMap = new Map();
    const linksMap = new Map();

    dataHistory.forEach(row => {
      const src = row.metrics?.src_ip;
      const dst = row.metrics?.dst_ip;
      const isAnomaly = row.anomaly;

      if (!src || !dst) return;

      // Assign types so we can color them differently
      if (!nodesMap.has(src)) nodesMap.set(src, { id: src, isThreat: isAnomaly, type: 'source' });
      if (!nodesMap.has(dst)) nodesMap.set(dst, { id: dst, isThreat: false, type: 'destination' });

      if (isAnomaly) {
        nodesMap.get(src).isThreat = true; // Mark source as malicious
      }

      // Link ID
      const linkId = `${src}-${dst}`;
      if (!linksMap.has(linkId)) {
        linksMap.set(linkId, { source: src, target: dst, isAnomaly, width: 1 });
      } else {
        const link = linksMap.get(linkId);
        link.width = Math.min(link.width + 0.5, 5); // Cap width
        if (isAnomaly) link.isAnomaly = true;
      }
    });

    return {
      nodes: Array.from(nodesMap.values()),
      links: Array.from(linksMap.values())
    };
  }, [dataHistory]);

  return (
    <>
      <div className="dashboard-header" style={{ marginBottom: '16px', zIndex: 10 }}>
        <div className="dashboard-title">
          <h1>Network Topology Map</h1>
          <p>Real-time node relationship and threat origin tracking</p>
        </div>
      </div>

      <div
        ref={containerRef}
        style={{
          flex: 1,
          backgroundColor: '#0b0f19', // Deep dark blue from references
          border: '1px solid #1e293b',
          borderRadius: '12px',
          overflow: 'hidden',
          position: 'relative'
        }}
      >
        {graphData.nodes.length === 0 ? (
          <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', color: '#64748b' }}>
            Awaiting Network Traffic...
          </div>
        ) : (
          <ForceGraph2D
            ref={graphRef}
            width={dimensions.width}
            height={dimensions.height}
            graphData={graphData}
            nodeRelSize={6}

            // Custom Node Canvas Drawing (Like the References)
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.id;
              const fontSize = 12 / globalScale;
              ctx.font = `${fontSize}px Sans-Serif`;

              // Determine Color
              let color = '#94a3b8'; // Default
              if (node.isThreat) color = '#ef4444'; // Red for attackers
              else if (node.type === 'source') color = '#10b981'; // Green for normal sources
              else if (node.type === 'destination') color = '#3b82f6'; // Blue for destinations

              // Draw Outer Glow/Ring (Static, Clean)
              ctx.beginPath();
              ctx.arc(node.x, node.y, 10, 0, 2 * Math.PI, false);
              ctx.fillStyle = node.isThreat ? 'rgba(239, 68, 68, 0.15)' :
                (node.type === 'source' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(59, 130, 246, 0.15)');
              ctx.fill();

              // Draw Inner Solid Circle
              ctx.beginPath();
              ctx.arc(node.x, node.y, 5, 0, 2 * Math.PI, false);
              ctx.fillStyle = color;
              ctx.fill();
              ctx.lineWidth = 1.5;
              ctx.strokeStyle = '#0b0f19'; // border to separate from lines
              ctx.stroke();

              // Draw Label Background
              const textWidth = ctx.measureText(label).width;
              const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.4);
              ctx.fillStyle = 'rgba(11, 15, 25, 0.8)';
              ctx.beginPath();
              ctx.roundRect(node.x - bckgDimensions[0] / 2, node.y + 12, bckgDimensions[0], bckgDimensions[1], 2);
              ctx.fill();

              // Draw Label Text
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillStyle = '#e2e8f0';
              ctx.fillText(label, node.x, node.y + 12 + bckgDimensions[1] / 2);
            }}

            // Link Styling
            linkColor={link => link.isAnomaly ? 'rgba(239, 68, 68, 0.6)' : 'rgba(59, 130, 246, 0.3)'}
            linkWidth={link => link.width}
            linkCurvature={0.25} // Curved lines like Reference Image 1

            // Particles
            linkDirectionalParticles={link => link.isAnomaly ? 4 : 2}
            linkDirectionalParticleWidth={link => link.isAnomaly ? 3 : 1.5}
            linkDirectionalParticleSpeed={link => link.isAnomaly ? 0.015 : 0.005}
            linkDirectionalParticleColor={link => link.isAnomaly ? '#ef4444' : '#60a5fa'}

            // Physics Engine Tuning (These are defaults, overridden in useEffect)
            d3AlphaDecay={0.02}
            d3VelocityDecay={0.3}
          />
        )}
      </div>
    </>
  );
}
