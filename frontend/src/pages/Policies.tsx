import type { SandboxProfile } from '../lib/api';

export default function Policies({ profiles }: { profiles: SandboxProfile[] }) {
  const RULES = [
    { rule: 'Deny shell access in production', status: 'enforced', severity: 'critical' },
    { rule: 'Read-only filesystem for all agents', status: 'enforced', severity: 'high' },
    { rule: 'Network allowlist-only in research mode', status: 'enforced', severity: 'high' },
    { rule: 'Database access scoped to declared resources', status: 'enforced', severity: 'critical' },
    { rule: 'Tool calls require intent match score ≥ 50', status: 'enforced', severity: 'critical' },
    { rule: 'Memory write requires attestation', status: 'enforced', severity: 'high' },
    { rule: 'MCP tools require cryptographic signature', status: 'enforced', severity: 'critical' },
    { rule: 'Agent delegation requires trust inheritance check', status: 'enforced', severity: 'high' },
  ];

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Enforcement Policies</div>
          <div className="page-title">Policy Manager</div>
          <div className="page-sub">{RULES.length} rules enforced · {profiles.length} sandbox profiles</div>
        </div>
        <span className="badge low">ALL ENFORCED</span>
      </div>

      <div className="grid-2">
        <div className="glass-card glow-green">
          <div className="card-header"><span className="card-title">Active Policy Rules</span></div>
          <div className="card-body" style={{ padding: 0 }}>
            <table className="data-table">
              <thead><tr><th>Rule</th><th>Severity</th><th>Status</th></tr></thead>
              <tbody>
                {RULES.map(r => (
                  <tr key={r.rule}>
                    <td style={{ fontSize: 12, color: 'var(--text-primary)' }}>{r.rule}</td>
                    <td><span className={`badge ${r.severity}`}>{r.severity}</span></td>
                    <td><span className="badge low">{r.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="glass-card glow-cyan">
          <div className="card-header"><span className="card-title">Fail-Closed Enforcement</span></div>
          <div className="card-body">
            <div className="callout" style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 10, letterSpacing: '0.15em', textTransform: 'uppercase', color: 'var(--green)', fontFamily: "'JetBrains Mono', monospace", marginBottom: 8 }}>Policy Mode</div>
              <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--green)', fontFamily: "'JetBrains Mono', monospace", textShadow: '0 0 20px var(--green)' }}>FAIL-CLOSED</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 10, lineHeight: 1.6 }}>
                When the policy engine cannot reach a decision within the required confidence threshold, execution is blocked automatically. No fallback to permissive mode.
              </div>
            </div>
            {profiles.map(p => (
              <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', boxShadow: '0 0 4px var(--green)' }} />
                <span style={{ fontSize: 13, color: 'var(--text-primary)', flex: 1 }}>{p.name}</span>
                <span className="badge info">{p.runtime}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
