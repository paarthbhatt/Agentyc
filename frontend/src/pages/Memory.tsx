import type { Incident, TelemetryEvent } from '../lib/api';

// Memory page uses incident evidence + telemetry payloads as "memory objects"
export default function Memory({ events, incidents }: { events: TelemetryEvent[]; incidents: Incident[] }) {
  const objects = [
    ...incidents.map(i => ({
      id: i.id, source: `incident:${i.category}`, preview: i.root_cause,
      trust: i.severity === 'critical' ? 8 : i.severity === 'high' ? 25 : 60,
      status: i.severity === 'critical' ? 'poisoned' : i.severity === 'high' ? 'suspicious' : 'active',
      indicators: i.response_actions.slice(0, 2),
      ts: i.created_at,
    })),
    ...events.filter(e => e.severity !== 'info').map(e => ({
      id: e.id, source: `telemetry:${e.event_type}`, preview: JSON.stringify(e.payload).slice(0, 80),
      trust: e.trust_score, status: e.risk_score > 60 ? 'suspicious' : 'active',
      indicators: [e.event_type], ts: e.occurred_at,
    })),
  ].slice(0, 20);

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Memory &amp; Context Security</div>
          <div className="page-title">Agent Memory Objects</div>
          <div className="page-sub">{objects.length} objects tracked</div>
        </div>
        <span className="badge high">{objects.filter(o => o.status === 'poisoned').length} POISONED</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 12 }}>
        {objects.length === 0 && (
          <div className="glass-card" style={{ gridColumn: '1/-1' }}>
            <div className="card-body"><div className="empty-state"><div className="empty-icon">◉</div>No memory objects</div></div>
          </div>
        )}
        {objects.map(obj => {
          const statusColor = obj.status === 'poisoned' ? 'var(--red)' : obj.status === 'suspicious' ? 'var(--amber)' : 'var(--green)';
          return (
            <div key={obj.id} className={`glass-card glow-${obj.status === 'poisoned' ? 'red' : obj.status === 'suspicious' ? 'amber' : 'green'}`}>
              <div style={{ padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: statusColor, boxShadow: `0 0 8px ${statusColor}`, flexShrink: 0, animation: obj.status === 'poisoned' ? 'blink 1s ease-in-out infinite' : undefined }} />
                  <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: statusColor, fontWeight: 600 }}>{obj.status.toUpperCase()}</span>
                  <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>{new Date(obj.ts).toLocaleTimeString()}</span>
                </div>
                <div style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-dim)', marginBottom: 6 }}>{obj.source}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.5 }}>{obj.preview}</div>
                {/* Trust bar */}
                <div style={{ marginBottom: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", marginBottom: 4 }}>
                    <span>TRUST LEVEL</span><span style={{ color: statusColor }}>{obj.trust}</span>
                  </div>
                  <div style={{ height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 999, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${obj.trust}%`, background: statusColor, boxShadow: `0 0 6px ${statusColor}`, borderRadius: 999, transition: 'width 700ms ease' }} />
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                  {obj.indicators.map(ind => (
                    <span key={ind} style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", background: `${statusColor}11`, border: `1px solid ${statusColor}33`, color: statusColor, padding: '2px 6px', borderRadius: 3 }}>{ind}</span>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
