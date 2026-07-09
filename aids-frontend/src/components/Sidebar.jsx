import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  ShieldAlert,
  BrainCircuit,
  Settings,
  Shield
} from 'lucide-react';

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <Shield className="logo-icon" size={28} />
          <span>ThreatShield AI</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <NavLink to="/dashboard" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
          <LayoutDashboard size={20} />
          <span>Dashboard</span>
        </NavLink>
        <NavLink to="/logs" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
          <ShieldAlert size={20} />
          <span>Anomaly Logs</span>
        </NavLink>
        <NavLink to="/topology" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
          <Network size={20} />
          <span>Network Topology</span>
        </NavLink>
        <NavLink to="/insights" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"} >
          <BrainCircuit size={20} />
          <span>Model Insights</span>
        </NavLink>
      </nav>
    </aside>
  );
}
