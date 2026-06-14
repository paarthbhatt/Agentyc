import BarChart from '../components/ui/BarChart';
import type { ToolTrust } from '../lib/api';

export default function ToolTrustPage({ tools }: { tools: ToolTrust[] }) {
  const sorted = [...tools].sort((a, b) => b.trust_score - a.trust_score);
  const suspicious = tools.filter(t => t.trust_score < 40 || t.status === 'suspicious');

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Tool Trust Analysis</div>
          <div className="page-title">Tool Trust Heatmap</div>
          <div className="page-sub">{tools.length} tools · {suspicious.length} suspicious</div>
        </div>
        {suspicious.length > 0 && <span className="badge critical">{suspicious.length} SUSPICIOUS</span>}
      </div>

      <div className="grid-2">
        <div className="glass-card glow-cyan">
          <div className="card-header"><span className="card-title">Trust Score Rankings</span></div>
          <div className="card-body">
            <BarChart items={sorted.map(t => ({ label: t.name, value: t.trust_score, subLabel: `${t.type} · ${t.status}` }))} />
          </div>
        </div>

        <div className="glass-card glow-red">
          <div className="card-header"><span className="card-title">Incident Rate</span></div>
          <div className="card-body">
            <BarChart items={sorted.filter(t => t.incident_count > 0).map(t => ({ label: t.name, value: t.incident_count, inverted: true, subLabel: t.type }))} />
            {sorted.every(t => t.incident_count === 0) && <div className="empty-state"><div className="empty-icon">✓</div>No incidents recorded</div>}
          </div>
        </div>
      </div>

      {/* Full table */}
      <div className="glass-card glow-cyan">
        <div className="card-header"><span className="card-title">Tool Registry</span></div>
        <div className="card-body" style={{ padding: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Tool</th><th>Type</th><th>Status</th><th>Trust</th><th>Incidents</th>
              </tr>
            </thead>
            <tbody>
              {tools.map(tool => (
                <tr key={tool.id}>
                  <td style={{ fontWeight: 600, color: 'var(--text-bright)' }}>{tool.name}</td>
                  <td className="mono-cell">{tool.type}</td>
                  <td><span className={`badge ${tool.status === 'suspicious' ? 'critical' : tool.status === 'verified' ? 'low' : 'medium'}`}>{tool.status}</span></td>
                  <td>
                    <div className="risk-bar-wrap">
                      <div className="risk-bar-track">
                        <div className={`risk-bar-fill ${tool.trust_score >= 75 ? 'low' : tool.trust_score >= 40 ? 'high' : 'critical'}`} style={{ width: `${tool.trust_score}%` }} />
                      </div>
                      <span className="risk-bar-label">{tool.trust_score}</span>
                    </div>
                  </td>
                  <td className="mono-cell" style={{ color: tool.incident_count > 0 ? 'var(--red)' : 'var(--text-dim)' }}>{tool.incident_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
