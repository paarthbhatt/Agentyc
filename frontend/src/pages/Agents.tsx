import ThreatRing from '../components/ui/ThreatRing';
import type { Agent } from '../lib/api';

function sev(s: number) { return s >= 75 ? 'critical' : s >= 50 ? 'high' : 'low'; }

export default function Agents({ agents }: { agents: Agent[] }) {
  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Agent Fleet</div>
          <div className="page-title">Registered Agents</div>
          <div className="page-sub">{agents.length} agents monitored across all environments</div>
        </div>
        <span className={`badge ${agents.length > 0 ? 'info' : 'low'}`}>{agents.length} TOTAL</span>
      </div>

      {agents.length === 0 ? (
        <div className="glass-card"><div className="card-body"><div className="empty-state"><div className="empty-icon">◈</div>No agents registered</div></div></div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {agents.map(agent => (
            <div key={agent.id} className={`glass-card glow-${sev(agent.risk_score) === 'critical' ? 'red' : sev(agent.risk_score) === 'high' ? 'amber' : 'cyan'}`}
              style={{ cursor: 'default' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 20, padding: '16px 20px' }}>
                {/* Status orb */}
                <div style={{ position: 'relative', width: 40, height: 40, flexShrink: 0 }}>
                  <div style={{
                    position: 'absolute', inset: '50%', transform: 'translate(-50%,-50%)',
                    width: 10, height: 10, borderRadius: '50%',
                    background: agent.status === 'active' ? 'var(--green)' : 'var(--text-dim)',
                    boxShadow: agent.status === 'active' ? '0 0 8px var(--green)' : 'none',
                  }} />
                  {agent.status === 'active' && (
                    <>
                      {[1, 2].map(r => (
                        <div key={r} style={{
                          position: 'absolute', inset: `calc(50% - ${r * 8}px)`,
                          borderRadius: '50%', border: '1px solid var(--green)',
                          animation: `orb-ring ${1.5 + r * 0.5}s ease-in-out infinite`,
                          animationDelay: `${r * 0.3}s`,
                        }} />
                      ))}
                    </>
                  )}
                </div>

                {/* Info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                    <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-bright)' }}>{agent.name}</span>
                    <span className={`badge ${agent.status === 'active' ? 'low' : 'medium'}`}>{agent.status}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
                    {[
                      ['Framework', agent.framework],
                      ['Owner', agent.owner],
                      ['Env', agent.environment],
                      ['Registered', new Date(agent.created_at).toLocaleDateString()],
                    ].map(([k, v]) => (
                      <div key={k}>
                        <div style={{ fontSize: 9, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.1em', textTransform: 'uppercase' }}>{k}</div>
                        <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>{v}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Risk ring */}
                <ThreatRing score={agent.risk_score} size={90} label="Risk" />

                {/* Trust ring */}
                <ThreatRing score={agent.trust_level} size={90} label="Trust" color={agent.trust_level < 40 ? '#ff3040' : agent.trust_level < 70 ? '#ffb700' : '#00ff88'} />

                {/* ID */}
                <div style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", maxWidth: 120, wordBreak: 'break-all', flexShrink: 0 }}>
                  {agent.id.slice(0, 8)}…
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
