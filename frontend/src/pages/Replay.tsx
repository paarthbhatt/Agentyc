import type { Incident, TelemetryEvent } from '../lib/api';

function sev(s: string) { return s === 'critical' ? 'critical' : s === 'high' ? 'high' : s === 'medium' ? 'medium' : 'info'; }

interface Props { incidents: Incident[]; replay: TelemetryEvent[]; selectedIncident: Incident | null; }

export default function Replay({ incidents, replay, selectedIncident }: Props) {
  const inc = selectedIncident ?? incidents[0];
  const intentScore = inc?.evidence?.intent_match_score;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Forensic Reconstruction</div>
          <div className="page-title">Attack Replay</div>
          <div className="page-sub">{inc?.session_id ?? 'No incident selected'}</div>
        </div>
      </div>

      <div className="grid-2">
        {/* Replay timeline */}
        <div className="glass-card glow-red">
          <div className="card-header">
            <span className="card-title">Event Sequence</span>
            <span className="badge critical">{replay.length} events</span>
          </div>
          <div className="card-body">
            {replay.length === 0 ? (
              <div className="empty-state"><div className="empty-icon">▷</div>No replay data</div>
            ) : (
              <div className="timeline">
                {replay.map((ev, idx) => (
                  <div key={ev.id} className="timeline-item">
                    <div className="timeline-dot-col">
                      <div style={{
                        width: 28, height: 28, borderRadius: 6,
                        background: 'rgba(0,0,0,0.5)',
                        border: `1px solid var(--border-dim)`,
                        display: 'grid', placeItems: 'center',
                        fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700,
                        color: 'var(--cyan)', flexShrink: 0,
                      }}>
                        {String(idx + 1).padStart(2, '0')}
                      </div>
                    </div>
                    <div className="timeline-content">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span className={`badge ${sev(ev.severity)}`}>{ev.severity}</span>
                        <div className="timeline-event-type">{ev.event_type}</div>
                      </div>
                      <div style={{ display: 'flex', gap: 16, marginBottom: 4 }}>
                        <div className="risk-bar-wrap" style={{ flex: 1 }}>
                          <span style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", minWidth: 28 }}>RISK</span>
                          <div className="risk-bar-track">
                            <div className={`risk-bar-fill ${ev.risk_score >= 75 ? 'critical' : ev.risk_score >= 50 ? 'high' : 'low'}`} style={{ width: `${ev.risk_score}%` }} />
                          </div>
                          <span className="risk-bar-label">{ev.risk_score}</span>
                        </div>
                        <div className="risk-bar-wrap" style={{ flex: 1 }}>
                          <span style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", minWidth: 28 }}>TRUST</span>
                          <div className="risk-bar-track">
                            <div className={`risk-bar-fill low`} style={{ width: `${ev.trust_score}%`, background: `linear-gradient(90deg, #064e3b, var(--green))` }} />
                          </div>
                          <span className="risk-bar-label">{ev.trust_score}</span>
                        </div>
                      </div>
                      <div className="timeline-payload">{JSON.stringify(ev.payload).slice(0, 100)}</div>
                      <div className="timeline-meta" style={{ marginTop: 4 }}>{new Date(ev.occurred_at).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Incident focus + intent score */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="callout">
            <div style={{ fontSize: 10, letterSpacing: '0.15em', textTransform: 'uppercase', color: 'var(--cyan)', fontFamily: "'JetBrains Mono', monospace", marginBottom: 6 }}>Cognitive Firewall</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-bright)', marginBottom: 8 }}>Intent Match Score</div>
            <div className={`hero-number ${typeof intentScore === 'number' && intentScore < 30 ? 'critical' : 'info'}`}>
              {typeof intentScore === 'number' || typeof intentScore === 'string' ? intentScore : '—'}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
              The firewall compares the approved user goal against the actual tool, action, resource, identity, memory influence, and trust chain before execution.
            </div>
          </div>

          {inc && (
            <div className="glass-card glow-red" style={{ flex: 1 }}>
              <div className="card-header"><span className="card-title">Incident Focus</span></div>
              <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <span className={`badge ${sev(inc.severity)}`}>{inc.severity}</span>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-bright)' }}>{inc.title}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>{inc.root_cause}</div>
                <div style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>Category: {inc.category}</div>
                <div className="incident-actions" style={{ marginTop: 4 }}>
                  {inc.response_actions.map(a => <span key={a} className="action-tag">{a}</span>)}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
