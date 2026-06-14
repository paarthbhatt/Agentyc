import ForceGraph from '../components/ui/ForceGraph';
import type { GraphResponse } from '../lib/api';

export default function GraphView({ graph }: { graph: GraphResponse | null }) {
  const nodeCount = graph?.nodes.length ?? 0;
  const edgeCount = graph?.edges.length ?? 0;
  const byType = graph?.nodes.reduce<Record<string, number>>((acc, n) => {
    acc[n.type] = (acc[n.type] ?? 0) + 1; return acc;
  }, {}) ?? {};

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Topology Visualisation</div>
          <div className="page-title">Security Graph</div>
          <div className="page-sub">{nodeCount} nodes · {edgeCount} edges · force-directed layout</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {Object.entries(byType).map(([type, count]) => (
            <span key={type} className="badge info">{type} {count}</span>
          ))}
        </div>
      </div>

      <div className="glass-card glow-violet" style={{ minHeight: 560 }}>
        <div className="card-body" style={{ padding: 16, height: 560 }}>
          {!graph || graph.nodes.length === 0 ? (
            <div className="empty-state" style={{ height: '100%' }}>
              <div className="empty-icon">⬡</div>
              <div>Select an agent to load its security graph</div>
            </div>
          ) : (
            <ForceGraph graph={graph} />
          )}
        </div>
      </div>

      {graph && (
        <div className="grid-3" style={{ marginTop: 16 }}>
          {graph.nodes.slice(0, 6).map(node => {
            const color = { agent: '#00d4ff', incident: '#ff3040', tool: '#a855f7' }[node.type] ?? '#ffb700';
            return (
              <div key={node.id} className="glass-card" style={{ '--glow': color } as React.CSSProperties}>
                <div className="card-body" style={{ padding: '14px 16px' }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}`, flexShrink: 0 }} />
                    <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{node.type}</span>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 6, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{node.label}</div>
                  <div style={{ display: 'flex', gap: 12 }}>
                    <div>
                      <div style={{ fontSize: 9, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>RISK</div>
                      <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: node.risk_score >= 75 ? 'var(--red)' : node.risk_score >= 50 ? 'var(--amber)' : 'var(--green)' }}>{node.risk_score}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>TRUST</div>
                      <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: 'var(--cyan)' }}>{node.trust_score}</div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
