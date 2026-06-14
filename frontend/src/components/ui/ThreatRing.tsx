interface Props {
  score: number;       // 0-100
  size?: number;
  label?: string;
  color?: string;
}

export default function ThreatRing({ score, size = 180, label = 'Global Risk', color }: Props) {
  const cx = size / 2, cy = size / 2;
  const radius = size / 2 - 16;
  const stroke = 10;
  const circumference = 2 * Math.PI * radius;
  const fill = (score / 100) * circumference;

  const resolvedColor = color ?? (score >= 75 ? '#ff3040' : score >= 50 ? '#ffb700' : score >= 25 ? '#00d4ff' : '#00ff88');
  const bg = score >= 75 ? 'rgba(255,48,64,0.08)' : score >= 50 ? 'rgba(255,183,0,0.08)' : 'rgba(0,212,255,0.06)';

  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        {/* Outer decorative rings */}
        <circle cx={cx} cy={cy} r={radius + 12} fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth={1} />
        <circle cx={cx} cy={cy} r={radius + 20} fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth={1}
          strokeDasharray="4 8" />

        {/* Background track */}
        <circle cx={cx} cy={cy} r={radius} fill={bg} stroke="rgba(255,255,255,0.06)" strokeWidth={stroke} />

        {/* Filled arc */}
        <circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke={resolvedColor}
          strokeWidth={stroke}
          strokeDasharray={`${fill} ${circumference}`}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${resolvedColor})`, transition: 'stroke-dasharray 800ms cubic-bezier(0.4,0,0.2,1)' }}
        />

        {/* Tick marks every 10% */}
        {Array.from({ length: 10 }, (_, i) => {
          const angle = (i / 10) * Math.PI * 2;
          const ox = cx + (radius + 14) * Math.cos(angle);
          const oy = cy + (radius + 14) * Math.sin(angle);
          const ix = cx + (radius + 8) * Math.cos(angle);
          const iy = cy + (radius + 8) * Math.sin(angle);
          return <line key={i} x1={ox} y1={oy} x2={ix} y2={iy} stroke="rgba(255,255,255,0.1)" strokeWidth={1} />;
        })}
      </svg>

      {/* Center label */}
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        gap: 2,
      }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: size * 0.25,
          fontWeight: 700,
          color: resolvedColor,
          lineHeight: 1,
          textShadow: `0 0 20px ${resolvedColor}`,
        }}>{score}</span>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 10,
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
          color: 'rgba(106,138,170,0.8)',
          marginTop: 2,
        }}>{label}</span>
      </div>
    </div>
  );
}
