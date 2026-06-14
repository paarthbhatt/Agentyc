import type { RedTeamScenario } from '../lib/api';

function sev(s: string) { return s === 'critical' ? 'critical' : s === 'high' ? 'high' : s === 'medium' ? 'medium' : 'low'; }

export default function RedTeam({ scenarios }: { scenarios: RedTeamScenario[] }) {
  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Adversarial Testing</div>
          <div className="page-title">Red Team Scenarios</div>
          <div className="page-sub">{scenarios.length} scenarios generated</div>
        </div>
        <span className="badge critical">{scenarios.filter(s => s.severity === 'critical').length} CRITICAL</span>
      </div>

      {scenarios.length === 0 ? (
        <div className="glass-card"><div className="card-body"><div className="empty-state"><div className="empty-icon">◎</div>No scenarios</div></div></div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {scenarios.map(sc => (
            <div key={sc.id} className={`glass-card glow-${sev(sc.severity) === 'critical' ? 'red' : sev(sc.severity) === 'high' ? 'amber' : 'cyan'}`}>
              <div style={{ padding: '16px 20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                  <span className={`badge ${sev(sc.severity)}`}>{sc.severity}</span>
                  <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-bright)', flex: 1 }}>{sc.name}</span>
                  <span className="badge info">{sc.category}</span>
                  <span className={`badge ${sc.status === 'passed' ? 'low' : sc.status === 'failed' ? 'critical' : 'medium'}`}>{sc.status}</span>
                </div>

                {/* Attack flow diagram */}
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8 }}>Attack Steps</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 0, flexWrap: 'wrap', gap: '8px 0' }}>
                    {sc.attack_steps.map((step, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center' }}>
                        <div style={{
                          background: 'rgba(255,48,64,0.08)', border: '1px solid rgba(255,48,64,0.2)',
                          borderRadius: 6, padding: '6px 12px', fontSize: 12, color: 'var(--text-muted)',
                          fontFamily: "'JetBrains Mono', monospace", position: 'relative',
                        }}>
                          <span style={{ position: 'absolute', top: -8, left: 8, fontSize: 9, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>0{i + 1}</span>
                          {step}
                        </div>
                        {i < sc.attack_steps.length - 1 && (
                          <div style={{ width: 24, height: 1, background: 'rgba(255,48,64,0.3)', position: 'relative' }}>
                            <div style={{ position: 'absolute', right: 0, top: -3, color: 'rgba(255,48,64,0.5)', fontSize: 8 }}>▶</div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6 }}>Expected Controls</div>
                  <div className="scenario-steps">
                    {sc.expected_controls.map(c => <span key={c} className="step-chip">{c}</span>)}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
