/** Horizontal bar-chart for tool trust / risk scores */
interface BarItem { label: string; value: number; inverted?: boolean; subLabel?: string; }
interface Props { items: BarItem[]; height?: number; }

function barColor(v: number, inverted: boolean) {
  const score = inverted ? 100 - v : v;
  if (score >= 75) return '#ff3040';
  if (score >= 50) return '#ffb700';
  return '#00ff88';
}

export default function BarChart({ items, height = 220 }: Props) {
  if (!items.length) return <div className="empty-state"><div className="empty-icon">📊</div>No data</div>;
  const max = Math.max(...items.map(i => i.value), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: '4px 0' }}>
      {items.map((item, idx) => {
        const pct = (item.value / max) * 100;
        const color = barColor(item.value, item.inverted ?? false);
        return (
          <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 130, flexShrink: 0, overflow: 'hidden' }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#c8dff0', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.label}</div>
              {item.subLabel && <div style={{ fontSize: 10, color: '#3a5070', fontFamily: "'JetBrains Mono', monospace" }}>{item.subLabel}</div>}
            </div>
            <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 999, overflow: 'hidden' }}>
              <div style={{
                height: '100%', borderRadius: 999,
                width: `${pct}%`,
                background: `linear-gradient(90deg, ${color}80, ${color})`,
                boxShadow: `0 0 8px ${color}60`,
                transition: 'width 700ms cubic-bezier(0.4,0,0.2,1)',
              }} />
            </div>
            <div style={{ width: 32, textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color, fontWeight: 700 }}>{item.value}</div>
          </div>
        );
      })}
    </div>
  );
}
