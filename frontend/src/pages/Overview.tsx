import ThreatRing from '../components/ui/ThreatRing';
import type { DashboardSummary, Agent, Incident, TelemetryEvent } from '../lib/api';

function scoreClass(s: number) { return s >= 75 ? 'critical' : s >= 50 ? 'high' : 'good'; }
function sevClass(s: string) { return s === 'critical' ? 'critical' : s === 'high' ? 'high' : s === 'medium' ? 'medium' : 'low'; }

interface Props {
  summary: DashboardSummary;
  agents: Agent[];
  incidents: Incident[];
  events: TelemetryEvent[];
}

export default function Overview({ summary, agents, incidents, events }: Props) {
  const topAgents = [...agents].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6);

  return (
    <div className="fade-in">
      {/* Command Banner */}
      <div className="command-banner mb-5">
        <div className="command-banner-text">
          <div className="eyebrow">Zero Trust Agent Runtime</div>
          <h2>Continuous verification across identity, intent, tools, memory, MCP &amp; delegation.</h2>
        </div>
        <div className="status-chips">
          {['EDR active', 'Firewall enforcing', 'MCP monitored', 'Replay recording'].map(s => (
            <div key={s} className="status-chip">
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#00ff88', boxShadow: '0 0 4px #00ff88', flexShrink: 0 }} />
              <b>{s.split(' ')[0]}</b> {s.split(' ').slice(1).join(' ')}
            </div>
          ))}
        </div>
      </div>

      {/* Stats + Ring */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 20, marginBottom: 20 }}>
        <div className="stat-grid" style={{ alignContent: 'start' }}>
          {[
            { label: 'Active Agents',    value: summary.active_agents,            cls: 'info',     accent: '#00d4ff' },
            { label: 'Global Risk',      value: summary.global_risk_score,        cls: scoreClass(summary.global_risk_score), accent: summary.global_risk_score >= 75 ? '#ff3040' : '#ffb700' },
            { label: 'Ongoing Attacks',  value: summary.ongoing_attacks,          cls: 'critical', accent: '#ff3040' },
            { label: 'Blocked Actions',  value: summary.blocked_actions,          cls: 'high',     accent: '#ffb700' },
            { label: 'Prompt Injection', value: summary.prompt_injection_attempts,cls: 'high',     accent: '#ffb700' },
            { label: 'Memory Poisoning', value: summary.memory_poisoning_alerts,  cls: 'high',     accent: '#a855f7' },
            { label: 'Trust Violations', value: summary.trust_violations,         cls: 'high',     accent: '#ffb700' },
            { label: 'Identity Violations',value: summary.identity_violations,    cls: 'critical', accent: '#ff3040' },
          ].map(({ label, value, cls, accent }) => (
            <div key={label} className="stat-card" style={{ '--stat-accent': accent } as React.CSSProperties}>
              <div className="stat-label">{label}</div>
              <div className={`stat-value ${cls}`}>{value}</div>
            </div>
          ))}
        </div>

        <div className="glass-card glow-cyan" style={{ padding: 24, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16, minWidth: 220 }}>
          <ThreatRing score={summary.global_risk_score} size={180} label="Global Risk" />
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
              Threat Level
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, color: summary.global_risk_score >= 75 ? 'var(--red)' : summary.global_risk_score >= 50 ? 'var(--amber)' : 'var(--cyan)', marginTop: 4 }}>
              {summary.global_risk_score >= 75 ? 'CRITICAL' : summary.global_risk_score >= 50 ? 'ELEVATED' : summary.global_risk_score >= 25 ? 'MODERATE' : 'NOMINAL'}
            </div>
          </div>
        </div>
      </div>

      {/* Live Timeline + Agent Leaderboard */}
      <div className="grid-2-1">
        <div className="glass-card glow-cyan">
          <div className="card-header">
            <span className="card-title">Live Attack Timeline</span>
            <span className="badge info">LIVE</span>
          </div>
          <div className="card-body">
            <div className="timeline">
              {events.length === 0 && <div className="empty-state"><div className="empty-icon">📡</div>No telemetry yet</div>}
              {events.map((ev, i) => (
                <div key={ev.id} className="timeline-item" style={{ animationDelay: `${i * 40}ms` }}>
                  <div className="timeline-dot-col">
                    <div className={`timeline-dot ${sevClass(ev.severity)}`} />
                    {i < events.length - 1 && <div className="timeline-line" />}
                  </div>
                  <div className="timeline-content">
                    <div className="timeline-event-type">{ev.event_type}</div>
                    <div className="timeline-meta">
                      R:{ev.risk_score} T:{ev.trust_score} · {new Date(ev.occurred_at).toLocaleTimeString()}
                    </div>
                    <div className="timeline-payload">{JSON.stringify(ev.payload).slice(0, 120)}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="glass-card glow-amber">
          <div className="card-header">
            <span className="card-title">Risk Leaderboard</span>
          </div>
          <div className="card-body">
            {topAgents.length === 0 && <div className="empty-state"><div className="empty-icon">◈</div>No agents</div>}
            {topAgents.map(a => {
              const color = a.risk_score >= 75 ? 'var(--red)' : a.risk_score >= 50 ? 'var(--amber)' : 'var(--green)';
              return (
                <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
                  <div style={{ position: 'relative', width: 8, height: 8, flexShrink: 0 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: a.status === 'active' ? 'var(--green)' : 'var(--text-dim)', boxShadow: a.status === 'active' ? '0 0 6px var(--green)' : 'none' }} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.name}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>{a.framework} · {a.environment}</div>
                  </div>
                  <div className="risk-bar-wrap" style={{ width: 100 }}>
                    <div className="risk-bar-track">
                      <div className={`risk-bar-fill ${a.risk_score >= 75 ? 'critical' : a.risk_score >= 50 ? 'high' : 'low'}`} style={{ width: `${a.risk_score}%` }} />
                    </div>
                    <span className="risk-bar-label" style={{ color }}>{a.risk_score}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent Incidents */}
      <div className="glass-card glow-red">
        <div className="card-header">
          <span className="card-title">Recent Incidents</span>
          <span className="badge critical">{incidents.length} OPEN</span>
        </div>
        <div className="card-body">
          {incidents.length === 0 && <div className="empty-state"><div className="empty-icon">✓</div>No incidents</div>}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 10 }}>
            {incidents.slice(0, 6).map(inc => (
              <div key={inc.id} className={`incident-card ${sevClass(inc.severity)}`}>
                <div className="incident-row-top">
                  <span className={`badge ${sevClass(inc.severity)}`}>{inc.severity}</span>
                  <span className="incident-title">{inc.title}</span>
                </div>
                <div className="incident-cause">{inc.root_cause}</div>
                <div className="incident-actions">
                  {inc.response_actions.slice(0, 3).map(a => (
                    <span key={a} className="action-tag">{a}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
