import { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';

export type SectionId =
  | 'overview' | 'agents' | 'incidents' | 'replay'
  | 'graph' | 'memory' | 'tools' | 'policies'
  | 'threats' | 'mcp' | 'redteam' | 'sandbox';

interface NavItem {
  id: SectionId;
  label: string;
  icon: string;
  accent: string;
  badge?: number;
  group: string;
}

const NAV: NavItem[] = [
  { id: 'overview',  label: 'Overview',        icon: '⬡', accent: '#00d4ff', group: 'COMMAND' },
  { id: 'agents',    label: 'Agents',           icon: '◈', accent: '#00d4ff', group: 'COMMAND' },
  { id: 'incidents', label: 'Incidents',        icon: '⚠', accent: '#ff3040', group: 'COMMAND' },
  { id: 'replay',    label: 'Attack Replay',    icon: '▷', accent: '#ff3040', group: 'COMMAND' },
  { id: 'graph',     label: 'Security Graph',   icon: '⬡', accent: '#a855f7', group: 'ANALYSIS' },
  { id: 'memory',    label: 'Memory',           icon: '◉', accent: '#a855f7', group: 'ANALYSIS' },
  { id: 'tools',     label: 'Tool Trust',       icon: '⚙', accent: '#ffb700', group: 'ANALYSIS' },
  { id: 'threats',   label: 'Threat Intel',     icon: '⬛', accent: '#ff3040', group: 'INTEL' },
  { id: 'mcp',       label: 'MCP Security',     icon: '⬢', accent: '#a855f7', group: 'INTEL' },
  { id: 'redteam',   label: 'Red Team',         icon: '◎', accent: '#ff3040', group: 'INTEL' },
  { id: 'policies',  label: 'Policies',         icon: '▣', accent: '#00ff88', group: 'CONTROL' },
  { id: 'sandbox',   label: 'Sandbox',          icon: '⬜', accent: '#00ff88', group: 'CONTROL' },
];

const GROUPS = ['COMMAND', 'ANALYSIS', 'INTEL', 'CONTROL'];

interface Props {
  active: SectionId;
  onNav: (id: SectionId) => void;
  incidentCount?: number;
}

export default function Sidebar({ active, onNav, incidentCount = 0 }: Props) {
  const { user, org, logout } = useAuth();
  const activeItem = NAV.find(n => n.id === active);
  const accent = activeItem?.accent ?? '#00d4ff';

  return (
    <aside className="sidebar" style={{ '--nav-accent': accent } as React.CSSProperties}>
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-logo">AS</div>
        <div className="sidebar-brand-text">
          <h1>Agent Sentinel</h1>
          <p>ZERO TRUST RUNTIME</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="sidebar-nav">
        {GROUPS.map(group => (
          <div key={group}>
            <div className="nav-section-label">{group}</div>
            {NAV.filter(n => n.group === group).map(item => (
              <div
                key={item.id}
                className={`nav-item ${active === item.id ? 'active' : ''}`}
                style={active === item.id ? { '--nav-accent': item.accent } as React.CSSProperties : {}}
                onClick={() => onNav(item.id)}
              >
                <span className="nav-icon" style={{ color: active === item.id ? item.accent : undefined, fontSize: 14 }}>
                  {item.icon}
                </span>
                <span>{item.label}</span>
                {item.id === 'incidents' && incidentCount > 0 && (
                  <span className="nav-badge">{incidentCount}</span>
                )}
              </div>
            ))}
          </div>
        ))}
      </nav>

      {/* User */}
      <div className="sidebar-footer">
        {org && (
          <div style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-dim)', letterSpacing: '0.08em', padding: '0 10px 8px', textTransform: 'uppercase' }}>
            {org.name}
          </div>
        )}
        <div className="sidebar-user">
          <div className="user-avatar">
            {(user?.email?.[0] ?? 'A').toUpperCase()}
          </div>
          <div className="user-info">
            <div className="user-email">{user?.email ?? 'admin'}</div>
            <div className="user-role">owner</div>
          </div>
          <button className="logout-btn" onClick={logout} title="Sign out">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
          </button>
        </div>
      </div>
    </aside>
  );
}
