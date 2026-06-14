import type { SandboxProfile } from '../lib/api';

const POLICY_COLORS: Record<string, string> = {
  deny_by_default: '#ff3040', allowlist_only: '#ffb700', disabled: '#00ff88',
  read_only: '#00d4ff', scoped: '#a855f7', none: '#00ff88',
};

function PolicyChip({ label, value }: { label: string; value: string }) {
  const color = POLICY_COLORS[value] ?? '#6a8aaa';
  return (
    <div style={{ flex: 1, minWidth: 80 }}>
      <div style={{ fontSize: 9, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color, fontWeight: 600 }}>{value}</div>
    </div>
  );
}

export default function Sandbox({ profiles }: { profiles: SandboxProfile[] }) {
  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Execution Containment</div>
          <div className="page-title">Sandbox Profiles</div>
          <div className="page-sub">{profiles.length} profiles configured</div>
        </div>
      </div>

      {profiles.length === 0 && (
        <div className="glass-card"><div className="card-body"><div className="empty-state"><div className="empty-icon">⬜</div>No sandbox profiles</div></div></div>
      )}

      <div className="grid-2">
        {profiles.map(p => (
          <div key={p.id} className="glass-card glow-green">
            <div className="card-header">
              <span className="card-title">{p.name}</span>
              <span className="badge info">{p.runtime}</span>
            </div>
            <div className="card-body">
              {/* Policy grid */}
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16, padding: '12px', background: 'rgba(0,0,0,0.3)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                <PolicyChip label="Network"    value={p.network_policy} />
                <PolicyChip label="Filesystem" value={p.filesystem_policy} />
                <PolicyChip label="Shell"      value={p.shell_policy} />
                <PolicyChip label="Database"   value={p.database_policy} />
              </div>

              {/* Allowed hosts */}
              {p.allowed_hosts.length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6 }}>Allowed Hosts</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {p.allowed_hosts.map(h => (
                      <span key={h} style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", background: 'rgba(0,255,136,0.06)', border: '1px solid rgba(0,255,136,0.2)', color: 'var(--green)', padding: '2px 8px', borderRadius: 4 }}>{h}</span>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-dim)', marginTop: 8 }}>
                Created {new Date(p.created_at).toLocaleDateString()}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
