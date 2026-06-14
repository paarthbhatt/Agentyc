import { useState } from 'react';
import type { Incident } from '../lib/api';

type Filter = 'all' | 'critical' | 'high' | 'medium' | 'low';
function sev(s: string) { return s === 'critical' ? 'critical' : s === 'high' ? 'high' : s === 'medium' ? 'medium' : 'low'; }

export default function Incidents({ incidents }: { incidents: Incident[] }) {
  const [filter, setFilter] = useState<Filter>('all');
  const [selected, setSelected] = useState<Incident | null>(null);

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const inc of incidents) counts[sev(inc.severity) as keyof typeof counts]++;

  const filtered = filter === 'all' ? incidents : incidents.filter(i => sev(i.severity) === filter);

  return (
    <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 420px' : '1fr', gap: 16 }}>
      <div>
        <div className="page-header">
          <div className="page-header-left">
            <div className="page-eyebrow">Security Incidents</div>
            <div className="page-title">Incident Queue</div>
          </div>
          {/* Filter chips */}
          <div style={{ display: 'flex', gap: 8 }}>
            {(['all', 'critical', 'high', 'medium', 'low'] as Filter[]).map(f => (
              <button key={f} onClick={() => setFilter(f)}
                style={{
                  padding: '6px 14px', borderRadius: 999, fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
                  fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', cursor: 'pointer',
                  background: filter === f ? (f === 'critical' ? 'rgba(255,48,64,0.2)' : f === 'high' ? 'rgba(255,183,0,0.2)' : 'rgba(0,212,255,0.1)') : 'transparent',
                  border: filter === f ? `1px solid ${f === 'critical' ? 'rgba(255,48,64,0.5)' : f === 'high' ? 'rgba(255,183,0,0.5)' : 'rgba(0,212,255,0.3)'}` : '1px solid var(--border-subtle)',
                  color: filter === f ? (f === 'critical' ? 'var(--red)' : f === 'high' ? 'var(--amber)' : 'var(--cyan)') : 'var(--text-muted)',
                  transition: 'all 160ms ease',
                }}>
                {f === 'all' ? `ALL ${incidents.length}` : `${f} ${counts[f as keyof typeof counts]}`}
              </button>
            ))}
          </div>
        </div>

        <div className="incident-list">
          {filtered.length === 0 && (
            <div className="glass-card"><div className="card-body"><div className="empty-state"><div className="empty-icon">✓</div>No incidents</div></div></div>
          )}
          {filtered.map(inc => (
            <div key={inc.id} className={`incident-card ${sev(inc.severity)}`}
              onClick={() => setSelected(selected?.id === inc.id ? null : inc)}
              style={{ borderColor: selected?.id === inc.id ? (inc.severity === 'critical' ? 'rgba(255,48,64,0.5)' : 'rgba(255,183,0,0.5)') : undefined, cursor: 'pointer' }}>
              <div className="incident-row-top">
                <span className={`badge ${sev(inc.severity)}`}>{inc.severity}</span>
                <span className="incident-title">{inc.title}</span>
                <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'nowrap' }}>
                  {new Date(inc.created_at).toLocaleString()}
                </span>
              </div>
              <div className="incident-cause">{inc.root_cause}</div>
              <div className="incident-actions">
                {inc.response_actions.map(a => <span key={a} className="action-tag">{a}</span>)}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Detail Panel */}
      {selected && (
        <div className="glass-card glow-red fade-in" style={{ alignSelf: 'start', position: 'sticky', top: 16 }}>
          <div className="card-header">
            <span className="card-title">Incident Detail</span>
            <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16, padding: '2px 6px', borderRadius: 4 }}>✕</button>
          </div>
          <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <span className={`badge ${sev(selected.severity)}`}>{selected.severity}</span>
              <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-bright)', marginTop: 8 }}>{selected.title}</div>
            </div>
            {[
              ['Session', selected.session_id],
              ['Category', selected.category],
              ['Status', selected.status],
              ['Root Cause', selected.root_cause],
            ].map(([k, v]) => (
              <div key={k}>
                <div style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4 }}>{k}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", wordBreak: 'break-all' }}>{v}</div>
              </div>
            ))}
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6 }}>Evidence</div>
              <pre style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", background: 'rgba(0,0,0,0.4)', padding: 10, borderRadius: 6, overflow: 'auto', maxHeight: 160 }}>
                {JSON.stringify(selected.evidence, null, 2)}
              </pre>
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6 }}>Response Actions</div>
              <div className="incident-actions">
                {selected.response_actions.map(a => <span key={a} className="action-tag">{a}</span>)}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
