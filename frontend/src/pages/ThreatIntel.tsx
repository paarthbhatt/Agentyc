import type { ThreatIntel } from '../lib/api';

const ICONS: Record<string, string> = {
  prompt_injection: '💉',
  memory_poisoning: '🧠',
  mcp_exploit: '⚡',
  default: '⚠',
};

export default function ThreatIntelPage({ threatIntel }: { threatIntel: ThreatIntel[] }) {
  const byType = threatIntel.reduce<Record<string, number>>((acc, t) => {
    acc[t.indicator_type] = (acc[t.indicator_type] ?? 0) + 1; return acc;
  }, {});

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Threat Intelligence</div>
          <div className="page-title">Threat Indicators</div>
          <div className="page-sub">{threatIntel.filter(t => t.active).length} active · {threatIntel.length} total</div>
        </div>
      </div>

      {/* Type breakdown */}
      <div className="stat-grid" style={{ marginBottom: 20 }}>
        {Object.entries(byType).map(([type, count]) => (
          <div key={type} className="stat-card" style={{ '--stat-accent': '#ff3040' } as React.CSSProperties}>
            <div className="stat-label">{type.replace(/_/g, ' ')}</div>
            <div className="stat-value critical">{count}</div>
          </div>
        ))}
      </div>

      <div className="glass-card glow-red">
        <div className="card-header">
          <span className="card-title">Indicators Feed</span>
          <span className="badge critical">LIVE</span>
        </div>
        <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {threatIntel.length === 0 && <div className="empty-state"><div className="empty-icon">⚠</div>No threat indicators</div>}
          {threatIntel.map(indicator => (
            <div key={indicator.id} className="threat-row">
              <div className="threat-indicator-icon">{ICONS[indicator.indicator_type] ?? ICONS.default}</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span className={`badge ${indicator.severity === 'critical' ? 'critical' : indicator.severity === 'high' ? 'high' : 'medium'}`}>{indicator.severity}</span>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', fontFamily: "'JetBrains Mono', monospace" }}>{indicator.indicator_type.replace(/_/g, ' ')}</span>
                  {!indicator.active && <span className="badge low">inactive</span>}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", marginBottom: 4 }}>
                  &quot;{indicator.value}&quot;
                </div>
                <div className="threat-confidence">
                  Confidence: <span style={{ color: 'var(--cyan)' }}>{indicator.confidence}%</span> · Source: {indicator.source}
                </div>
                <div className="threat-tags">
                  {indicator.tags.map(t => <span key={t} className="threat-tag">{t}</span>)}
                </div>
              </div>
              {/* Mini confidence bar */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                <svg width="40" height="40" style={{ transform: 'rotate(-90deg)' }}>
                  <circle cx="20" cy="20" r="16" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="4"/>
                  <circle cx="20" cy="20" r="16" fill="none"
                    stroke={indicator.confidence > 80 ? '#ff3040' : indicator.confidence > 60 ? '#ffb700' : '#00d4ff'}
                    strokeWidth="4" strokeLinecap="round"
                    strokeDasharray={`${(indicator.confidence / 100) * 100.5} 100.5`}
                    style={{ filter: 'drop-shadow(0 0 3px currentColor)' }}
                  />
                </svg>
                <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-dim)' }}>{indicator.confidence}%</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
