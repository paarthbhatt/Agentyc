import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { Agent, BehaviorBaseline, GraphResponse, Incident, TelemetryEvent } from '../lib/api';
import ForceGraph from '../components/ui/ForceGraph';
import ThreatRing from '../components/ui/ThreatRing';

function sev(s: number) {
  if (s >= 75) return 'critical';
  if (s >= 50) return 'high';
  return 'good';
}

export default function AgentDetail() {
  const { id } = useParams<{ id: string }>();
  const [agent, setAgent] = useState<Agent | null>(null);
  const [baseline, setBaseline] = useState<BehaviorBaseline | null>(null);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [allIncidents, setAllIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        // Agent list is small; find the one we need, then load full detail
        const agents = await api.agents();
        const found = agents.find(a => a.id === id) ?? null;
        if (!found) {
          if (!cancelled) {
            setError(`Agent not found: ${id}`);
            setLoading(false);
          }
          return;
        }
        if (cancelled) return;
        setAgent(found);

        const [eventData, graphData, baselineData, incidentData] = await Promise.all([
          api.events(id!),
          api.graph(id!),
          api.baseline(id!),
          api.incidents(),
        ]);

        if (cancelled) return;
        setEvents(eventData);
        setGraph(graphData);
        setBaseline(baselineData);
        setAllIncidents(incidentData);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load agent detail');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();
    return () => { cancelled = true; };
  }, [id]);

  const agentIncidents = allIncidents.filter(i => i.agent_id === id);

  if (loading) {
    return (
      <div className="fade-in">
        <div style={{
          display: 'flex', alignItems: 'center', gap: 12, padding: '20px 0',
          color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
        }}>
          <div style={{
            width: 16, height: 16, border: '2px solid var(--border-dim)',
            borderTopColor: 'var(--cyan)', borderRadius: '50%', animation: 'spin 0.8s linear infinite',
          }} />
          LOADING AGENT DETAIL…
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      </div>
    );
  }

  if (error || !agent) {
    return (
      <div className="fade-in">
        <div className="glass-card" style={{ padding: 24 }}>
          <div style={{ color: 'var(--red)', fontSize: 13, fontFamily: "'JetBrains Mono', monospace" }}>
            ⚠ {error ?? 'Agent not found'}
          </div>
          <Link to="/agents" style={{ color: 'var(--cyan)', fontSize: 12, marginTop: 8, display: 'inline-block' }}>
            ← Back to Agents
          </Link>
        </div>
      </div>
    );
  }

  const riskColor = agent.risk_score >= 75 ? '#ff3040' : agent.risk_score >= 50 ? '#ffb700' : '#00d4ff';
  const trustColor = agent.trust_level < 40 ? '#ff3040' : agent.trust_level < 70 ? '#ffb700' : '#00ff88';

  return (
    <div className="fade-in">
      {/* Header + identity */}
      <div className="glass-card glow-cyan" style={{ marginBottom: 16 }}>
        <div className="card-body" style={{ padding: '20px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 20, flexWrap: 'wrap' }}>
            {/* Status orb */}
            <div style={{ position: 'relative', width: 56, height: 56, flexShrink: 0 }}>
              <div style={{
                position: 'absolute', inset: '50%', transform: 'translate(-50%,-50%)',
                width: 14, height: 14, borderRadius: '50%',
                background: agent.status === 'active' ? 'var(--green)' : 'var(--text-dim)',
                boxShadow: agent.status === 'active' ? '0 0 10px var(--green)' : 'none',
              }} />
              {agent.status === 'active' && (
                <>
                  {[1, 2].map(r => (
                    <div key={r} style={{
                      position: 'absolute', inset: `calc(50% - ${r * 10}px)`,
                      borderRadius: '50%', border: '1px solid var(--green)',
                      animation: `orb-ring ${1.5 + r * 0.5}s ease-in-out infinite`,
                      animationDelay: `${r * 0.3}s`,
                    }} />
                  ))}
                </>
              )}
            </div>

            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-bright)', fontFamily: "'JetBrains Mono', monospace" }}>
                  {agent.name}
                </span>
                <span style={{
                  fontSize: 10, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700,
                  textTransform: 'uppercase', letterSpacing: '0.1em', padding: '2px 10px', borderRadius: 999,
                  background: agent.status === 'active' ? 'rgba(0,255,136,0.1)' : 'rgba(255,255,255,0.05)',
                  border: `1px solid ${agent.status === 'active' ? 'rgba(0,255,136,0.3)' : 'var(--border-subtle)'}`,
                  color: agent.status === 'active' ? 'var(--green)' : 'var(--text-dim)',
                }}>{agent.status}</span>
              </div>

              <div style={{
                display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 12,
              }}>
                {[
                  ['ID', agent.id],
                  ['Framework', agent.framework],
                  ['Owner', agent.owner],
                  ['Environment', agent.environment],
                  ['Registered', new Date(agent.created_at).toLocaleDateString()],
                ].map(([k, v]) => (
                  <div key={k}>
                    <div style={{
                      fontSize: 9, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace",
                      letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 3,
                    }}>{k}</div>
                    <div style={{
                      fontSize: 12, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace",
                      wordBreak: 'break-all',
                    }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Rings */}
            <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexShrink: 0 }}>
              <div style={{ textAlign: 'center' }}>
                <ThreatRing score={agent.risk_score} size={140} label="Risk" />
                <div style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: riskColor, marginTop: 4, fontWeight: 700 }}>
                  {agent.risk_score}/100
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <ThreatRing score={agent.trust_level} size={140} label="Trust" color={trustColor} />
                <div style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: trustColor, marginTop: 4, fontWeight: 700 }}>
                  {agent.trust_level}/100
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="stat-grid" style={{ marginBottom: 16 }}>
        <div className="stat-card" style={{ '--stat-accent': riskColor } as React.CSSProperties}>
          <div className="stat-label">Risk Score</div>
          <div className={`stat-value ${sev(agent.risk_score)}`}>{agent.risk_score}</div>
        </div>
        <div className="stat-card" style={{ '--stat-accent': trustColor } as React.CSSProperties}>
          <div className="stat-label">Trust Level</div>
          <div className={`stat-value ${agent.trust_level < 40 ? 'critical' : agent.trust_level < 70 ? 'high' : 'good'}`}>
            {agent.trust_level}
          </div>
        </div>
        <div className="stat-card" style={{ '--stat-accent': '#00d4ff' } as React.CSSProperties}>
          <div className="stat-label">Recent Events</div>
          <div className="stat-value info">{events.length}</div>
        </div>
        <div className="stat-card" style={{ '--stat-accent': '#ff3040' } as React.CSSProperties}>
          <div className="stat-label">Active Incidents</div>
          <div className={`stat-value ${agentIncidents.length > 0 ? 'critical' : 'good'}`}>
            {agentIncidents.length}
          </div>
        </div>
        {baseline && (
          <div className="stat-card" style={{ '--stat-accent': '#a855f7' } as React.CSSProperties}>
            <div className="stat-label">Anomalies</div>
            <div className={`stat-value ${baseline.anomaly_count > 0 ? 'high' : 'good'}`}>
              {baseline.anomaly_count}
            </div>
          </div>
        )}
      </div>

      <div className="grid-2-1">
        {/* Recent Telemetry Events TABLE */}
        <div className="glass-card glow-cyan">
          <div className="card-header">
            <span className="card-title">Recent Telemetry Events</span>
            <span className="badge info">{events.length} events</span>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            {events.length === 0 ? (
              <div className="empty-state" style={{ padding: '24px 0' }}>
                <div className="empty-icon">📡</div>No events recorded
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Trust</th>
                    <th>Payload (truncated)</th>
                  </tr>
                </thead>
                <tbody>
                  {events.slice(0, 20).map(ev => (
                    <tr key={ev.id}>
                      <td className="mono-cell" style={{ fontSize: 11 }}>
                        {new Date(ev.occurred_at).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 600 }}>{ev.event_type}</td>
                      <td>
                        <span className={`badge ${sev(ev.risk_score) === 'critical' ? 'critical' : sev(ev.risk_score) === 'high' ? 'high' : 'low'}`}>
                          {ev.severity}
                        </span>
                      </td>
                      <td className="mono-cell" style={{ color: ev.risk_score >= 75 ? 'var(--red)' : '#ffb700' }}>
                        {ev.risk_score}
                      </td>
                      <td className="mono-cell" style={{ color: '#00d4ff' }}>{ev.trust_score}</td>
                      <td className="mono-cell" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10, color: 'var(--text-dim)' }}>
                        {JSON.stringify(ev.payload).slice(0, 60)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Recent Incidents */}
          <div className="glass-card glow-red">
            <div className="card-header">
              <span className="card-title">Recent Incidents</span>
              <span className={`badge ${agentIncidents.length > 0 ? 'critical' : 'low'}`}>
                {agentIncidents.length}
              </span>
            </div>
            <div className="card-body">
              {agentIncidents.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">✓</div>
                  <div>No active incidents for this agent</div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {agentIncidents.slice(0, 10).map(inc => (
                    <div key={inc.id} className={`incident-card ${sev(inc.severity === 'critical' ? 100 : inc.severity === 'high' ? 75 : 50) === 'critical' ? 'critical' : sev(inc.severity === 'critical' ? 100 : inc.severity === 'high' ? 75 : 50) === 'high' ? 'high' : 'low'}`}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                        <span className={`badge ${sev(inc.severity === 'critical' ? 100 : inc.severity === 'high' ? 75 : 50) === 'critical' ? 'critical' : sev(inc.severity === 'critical' ? 100 : inc.severity === 'high' ? 75 : 50) === 'high' ? 'high' : 'medium'}`}>
                          {inc.severity}
                        </span>
                        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-bright)', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {inc.title}
                        </span>
                        <span style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>
                          {new Date(inc.created_at).toLocaleDateString()}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>
                        {inc.root_cause?.slice(0, 80)}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Cognitive Firewall Actions */}
          <div className="glass-card glow-violet">
            <div className="card-header">
              <span className="card-title">Cognitive Firewall Actions</span>
              <span className="badge info">{baseline ? (baseline.normal_actions?.length || 0) + (baseline.normal_tools?.length || 0) : 0} rules</span>
            </div>
            <div className="card-body">
              {!baseline || ((baseline.normal_actions?.length || 0) === 0 && (baseline.normal_tools?.length || 0) === 0) ? (
                <div className="empty-state">
                  <div className="empty-icon">🛡</div>
                  <div>No baseline recorded for this agent yet</div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4 }}>
                    Normal Tools
                  </div>
                  {(baseline.normal_tools || []).map(tool => (
                    <div key={tool} style={{
                      display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px',
                      background: 'rgba(0,255,136,0.04)', borderRadius: 6, border: '1px solid rgba(0,255,136,0.1)',
                    }}>
                      <span style={{ fontSize: 10, color: 'var(--green)', fontFamily: "'JetBrains Mono', monospace" }}>✓</span>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", flex: 1 }}>{tool}</span>
                      <span className="badge low" style={{ fontSize: 9 }}>ALLOWED</span>
                    </div>
                  ))}

                  <div style={{
                    fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace",
                    letterSpacing: '0.1em', textTransform: 'uppercase', marginTop: 12, marginBottom: 4,
                  }}>
                    Normal Actions
                  </div>
                  {(baseline.normal_actions || []).map(action => (
                    <div key={action} style={{
                      display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px',
                      background: 'rgba(0,212,255,0.04)', borderRadius: 6, border: '1px solid rgba(0,212,255,0.1)',
                    }}>
                      <span style={{ fontSize: 10, color: 'var(--cyan)', fontFamily: "'JetBrains Mono', monospace" }}>⬡</span>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", flex: 1 }}>{action}</span>
                      <span className="badge info" style={{ fontSize: 9 }}>NORMAL</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Graph Preview */}
          <div className="glass-card glow-violet" style={{ minHeight: 360 }}>
            <div className="card-header">
              <span className="card-title">Agent Security Graph</span>
              <span className="badge info">
                {graph ? `${graph.nodes.length} nodes` : '—'}
              </span>
            </div>
            <div className="card-body" style={{ height: 320 }}>
              {!graph || graph.nodes.length === 0 ? (
                <div className="empty-state" style={{ height: '100%' }}>
                  <div className="empty-icon">⬡</div>
                  <div>No graph data available</div>
                </div>
              ) : (
                <ForceGraph graph={graph} />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
