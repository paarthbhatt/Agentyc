import { useEffect, useState } from 'react';
import { api, PolicyPack, SandboxProfile } from '../lib/api';

export default function Policies() {
  const [profiles, setProfiles] = useState<SandboxProfile[]>([]);
  const [policies, setPolicies] = useState<PolicyPack[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [profData, polData] = await Promise.all([
          api.sandboxProfiles(),
          api.policies(),
        ]);
        setProfiles(profData);
        setPolicies(polData);
      } catch (err) {
        console.error("Failed to load policies", err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return <div className="fade-in" style={{ padding: 20 }}>Loading policies...</div>;
  }

  const activePolicy = policies.find(p => p.is_active) || policies[0];

  const rules = activePolicy ? [
    { rule: `Intent match score must be ≥ ${activePolicy.intent_match_threshold}`, status: 'enforced', severity: 'critical' },
    { rule: `Tool trust score must be ≥ ${activePolicy.tool_trust_threshold}`, status: 'enforced', severity: 'high' },
    { rule: `Memory trust score must be ≥ ${activePolicy.memory_trust_threshold}`, status: 'enforced', severity: 'high' },
    { rule: `Enforcement Mode: ${activePolicy.enforcement_mode.toUpperCase()}`, status: 'enforced', severity: 'critical' },
  ] : [];

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Enforcement Policies</div>
          <div className="page-title">{activePolicy ? activePolicy.name : "Policy Manager"}</div>
          <div className="page-sub">{rules.length} active rules · {profiles.length} sandbox profiles</div>
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
                {rules.map((r, i) => (
                  <tr key={i}>
                    <td style={{ fontSize: 12, color: 'var(--text-primary)' }}>{r.rule}</td>
                    <td><span className={`badge ${r.severity}`}>{r.severity}</span></td>
                    <td><span className="badge low">{r.status}</span></td>
                  </tr>
                ))}
                {rules.length === 0 && (
                  <tr><td colSpan={3} style={{ textAlign: "center", padding: 20, color: "var(--text-muted)" }}>No active policies</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="glass-card glow-cyan">
          <div className="card-header"><span className="card-title">Enforcement Status</span></div>
          <div className="card-body">
            <div className="callout" style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 10, letterSpacing: '0.15em', textTransform: 'uppercase', color: 'var(--green)', fontFamily: "'JetBrains Mono', monospace", marginBottom: 8 }}>Global Mode</div>
              <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--green)', fontFamily: "'JetBrains Mono', monospace", textShadow: '0 0 20px var(--green)' }}>
                {activePolicy ? (activePolicy.enforcement_mode === "block" ? "FAIL-CLOSED" : "AUDIT ONLY") : "FAIL-CLOSED"}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 10, lineHeight: 1.6 }}>
                {activePolicy?.description || "Execution defaults strictly to blocked unless explicitly allowed by thresholds."}
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
