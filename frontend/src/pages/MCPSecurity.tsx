import type { MCPAssessment } from '../lib/api';
import ThreatRing from '../components/ui/ThreatRing';

export default function MCPSecurity({ assessments }: { assessments: MCPAssessment[] }) {
  const blocked = assessments.filter(a => a.verdict === 'blocked').length;
  const suspicious = assessments.filter(a => a.verdict === 'suspicious').length;
  const approved = assessments.filter(a => a.verdict === 'approved').length;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Model Context Protocol</div>
          <div className="page-title">MCP Security</div>
          <div className="page-sub">{assessments.length} assessments</div>
        </div>
        {blocked > 0 && <span className="badge critical">{blocked} BLOCKED</span>}
      </div>

      <div className="stat-grid" style={{ marginBottom: 20 }}>
        {[
          { label: 'Blocked',    value: blocked,    cls: 'critical', accent: '#ff3040' },
          { label: 'Suspicious', value: suspicious,  cls: 'high',     accent: '#ffb700' },
          { label: 'Approved',   value: approved,   cls: 'good',     accent: '#00ff88' },
          { label: 'Total',      value: assessments.length, cls: 'info', accent: '#00d4ff' },
        ].map(({ label, value, cls, accent }) => (
          <div key={label} className="stat-card" style={{ '--stat-accent': accent } as React.CSSProperties}>
            <div className="stat-label">{label}</div>
            <div className={`stat-value ${cls}`}>{value}</div>
          </div>
        ))}
      </div>

      <div className="glass-card glow-violet">
        <div className="card-header"><span className="card-title">Assessment Results</span></div>
        <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {assessments.length === 0 && <div className="empty-state"><div className="empty-icon">⬢</div>No MCP assessments</div>}
          {assessments.map(a => {
            const verdictColor = a.verdict === 'blocked' ? 'var(--red)' : a.verdict === 'suspicious' ? 'var(--amber)' : 'var(--green)';
            return (
              <div key={a.id} className="glass-card" style={{ border: `1px solid ${verdictColor}33` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '14px 16px' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                      <span className={`badge ${a.verdict === 'blocked' ? 'critical' : a.verdict === 'suspicious' ? 'high' : 'low'}`}>{a.verdict}</span>
                      <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-bright)' }}>{a.server_name}</span>
                      <span style={{ fontSize: 12, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>/ {a.tool_name}</span>
                    </div>
                    <div style={{ display: 'flex', gap: 20, marginBottom: 8 }}>
                      <div className="risk-bar-wrap" style={{ flex: 1 }}>
                        <span style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", minWidth: 36 }}>RISK</span>
                        <div className="risk-bar-track">
                          <div className={`risk-bar-fill ${a.risk_score >= 75 ? 'critical' : a.risk_score >= 50 ? 'high' : 'low'}`} style={{ width: `${a.risk_score}%` }} />
                        </div>
                        <span className="risk-bar-label">{a.risk_score}</span>
                      </div>
                      <div className="risk-bar-wrap" style={{ flex: 1 }}>
                        <span style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", minWidth: 36 }}>TRUST</span>
                        <div className="risk-bar-track">
                          <div className="risk-bar-fill low" style={{ width: `${a.trust_score}%` }} />
                        </div>
                        <span className="risk-bar-label">{a.trust_score}</span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {a.findings.map(f => (
                        <span key={f} className="step-chip" style={{ background: 'rgba(255,48,64,0.06)', borderColor: 'rgba(255,48,64,0.15)', color: 'rgba(255,100,110,0.9)' }}>{f}</span>
                      ))}
                    </div>
                  </div>
                  <ThreatRing score={a.risk_score} size={80} label="Risk" />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
