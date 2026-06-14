import { useEffect, useRef, useState } from 'react';
import type { GraphResponse } from '../../lib/api';

interface Props { graph: GraphResponse | null; }

const NODE_COLORS: Record<string, string> = {
  agent:    '#00d4ff',
  incident: '#ff3040',
  tool:     '#a855f7',
  memory:   '#00ff88',
  default:  '#ffb700',
};

const RADIUS = 22;
const LINK_DIST = 130;
const REPULSE = 4500;
const ALPHA_DECAY = 0.015;
const SPRING_K = 0.04;

type Vec2 = { x: number; y: number };

interface SimNode {
  id: string; label: string; type: string; risk_score: number; trust_score: number;
  x: number; y: number; vx: number; vy: number; fx?: number; fy?: number;
}

interface SimLink { source: string; target: string; }

function runTick(nodes: SimNode[], links: SimLink[], alpha: number) {
  /* repulsion */
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      const dx = b.x - a.x || 0.01;
      const dy = b.y - a.y || 0.01;
      const dist2 = dx * dx + dy * dy;
      const force = (REPULSE * alpha) / dist2;
      const fx = force * dx / Math.sqrt(dist2);
      const fy = force * dy / Math.sqrt(dist2);
      a.vx -= fx; a.vy -= fy;
      b.vx += fx; b.vy += fy;
    }
  }
  /* spring */
  for (const link of links) {
    const a = nodes.find(n => n.id === link.source);
    const b = nodes.find(n => n.id === link.target);
    if (!a || !b) continue;
    const dx = b.x - a.x, dy = b.y - a.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const delta = (dist - LINK_DIST) * SPRING_K * alpha;
    const fx = (dx / dist) * delta;
    const fy = (dy / dist) * delta;
    a.vx += fx; a.vy += fy;
    b.vx -= fx; b.vy -= fy;
  }
  /* centering */
  for (const n of nodes) {
    if (!n.fx) n.vx += (0 - n.x) * 0.015 * alpha;
    if (!n.fy) n.vy += (0 - n.y) * 0.015 * alpha;
  }
  /* integrate */
  for (const n of nodes) {
    if (n.fx !== undefined) { n.x = n.fx; n.y = n.fy!; continue; }
    n.vx *= 0.7; n.vy *= 0.7;
    n.x += n.vx; n.y += n.vy;
  }
}

export default function ForceGraph({ graph }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const simRef = useRef<{ nodes: SimNode[]; links: SimLink[]; alpha: number; animId: number } | null>(null);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const dragging = useRef<{ id: string; offX: number; offY: number } | null>(null);
  const [dims, setDims] = useState({ w: 800, h: 500 });

  /* Build simulation when graph changes */
  useEffect(() => {
    if (!graph) return;
    const canvas = canvasRef.current!;
    const w = canvas.clientWidth || 800;
    const h = canvas.clientHeight || 500;
    setDims({ w, h });
    canvas.width = w;
    canvas.height = h;

    const cx = w / 2, cy = h / 2;
    const angle = (i: number) => (i / graph.nodes.length) * Math.PI * 2;
    const r0 = Math.min(w, h) * 0.3;

    const nodes: SimNode[] = graph.nodes.map((n, i) => ({
      ...n,
      x: cx + Math.cos(angle(i)) * r0,
      y: cy + Math.sin(angle(i)) * r0,
      vx: 0, vy: 0,
    }));

    const links: SimLink[] = graph.edges.map(e => ({ source: e.source, target: e.target }));

    if (simRef.current) cancelAnimationFrame(simRef.current.animId);
    let alpha = 1;

    function tick() {
      alpha = Math.max(0.001, alpha - ALPHA_DECAY);
      runTick(nodes, links, alpha);
      draw(canvas, nodes, links, hoveredId);
      const id = requestAnimationFrame(tick);
      simRef.current = { nodes, links, alpha, animId: id };
    }

    simRef.current = { nodes, links, alpha, animId: requestAnimationFrame(tick) };
    return () => { if (simRef.current) cancelAnimationFrame(simRef.current.animId); };
  }, [graph]);

  /* Hover & drag */
  function toCanvas(e: React.MouseEvent<HTMLCanvasElement>): Vec2 {
    const r = canvasRef.current!.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  }

  function nodeAt(pt: Vec2): SimNode | null {
    if (!simRef.current) return null;
    for (const n of simRef.current.nodes) {
      const dx = pt.x - (n.x + dims.w / 2), dy = pt.y - (n.y + dims.h / 2);
      if (Math.sqrt(dx * dx + dy * dy) <= RADIUS + 4) return n;
    }
    return null;
  }

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', minHeight: 480 }}>
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', display: 'block', cursor: dragging.current ? 'grabbing' : 'grab', borderRadius: 12 }}
        onMouseMove={e => {
          const pt = toCanvas(e);
          const n = nodeAt(pt);
          setHoveredId(n?.id ?? null);
          if (dragging.current && simRef.current) {
            const d = dragging.current;
            const dn = simRef.current.nodes.find(x => x.id === d.id);
            if (dn) {
              dn.fx = pt.x - dims.w / 2 + d.offX;
              dn.fy = pt.y - dims.h / 2 + d.offY;
              dn.x = dn.fx; dn.y = dn.fy;
            }
          }
        }}
        onMouseDown={e => {
          const pt = toCanvas(e);
          const n = nodeAt(pt);
          if (n) dragging.current = { id: n.id, offX: n.x - (pt.x - dims.w / 2), offY: n.y - (pt.y - dims.h / 2) };
        }}
        onMouseUp={() => {
          if (dragging.current && simRef.current) {
            const dn = simRef.current.nodes.find(x => x.id === dragging.current!.id);
            if (dn) { delete dn.fx; delete dn.fy; }
          }
          dragging.current = null;
        }}
        onMouseLeave={() => {
          setHoveredId(null);
          dragging.current = null;
        }}
      />
      {/* Legend */}
      <div style={{ position: 'absolute', bottom: 16, right: 16, display: 'flex', flexDirection: 'column', gap: 6, background: 'rgba(4,8,14,0.85)', border: '1px solid rgba(0,212,255,0.12)', borderRadius: 8, padding: '10px 14px', backdropFilter: 'blur(12px)' }}>
        {Object.entries(NODE_COLORS).filter(([k]) => k !== 'default').map(([type, color]) => (
          <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#6a8aaa', textTransform: 'capitalize', letterSpacing: '0.06em' }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}`, flexShrink: 0 }} />
            {type}
          </div>
        ))}
        <div style={{ fontSize: 10, color: '#3a5070', marginTop: 4, fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.04em' }}>drag to reposition</div>
      </div>
    </div>
  );
}

function draw(canvas: HTMLCanvasElement, nodes: SimNode[], links: SimLink[], hoveredId: string | null) {
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const w = canvas.width, h = canvas.height;
  const cx = w / 2, cy = h / 2;
  ctx.clearRect(0, 0, w, h);

  /* Background grid */
  ctx.strokeStyle = 'rgba(0,212,255,0.04)';
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
  for (let y = 0; y < h; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }

  /* Links */
  for (const link of links) {
    const a = nodes.find(n => n.id === link.source);
    const b = nodes.find(n => n.id === link.target);
    if (!a || !b) continue;
    const ax = a.x + cx, ay = a.y + cy;
    const bx = b.x + cx, by = b.y + cy;
    const grad = ctx.createLinearGradient(ax, ay, bx, by);
    const ca = NODE_COLORS[a.type] ?? NODE_COLORS.default;
    const cb = NODE_COLORS[b.type] ?? NODE_COLORS.default;
    grad.addColorStop(0, ca + '44');
    grad.addColorStop(1, cb + '44');
    ctx.strokeStyle = grad;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(ax, ay);
    /* slight curve */
    const mx = (ax + bx) / 2, my = (ay + by) / 2;
    ctx.quadraticCurveTo(mx, my - 20, bx, by);
    ctx.stroke();
  }

  /* Nodes */
  for (const node of nodes) {
    const nx = node.x + cx, ny = node.y + cy;
    const color = NODE_COLORS[node.type] ?? NODE_COLORS.default;
    const isHov = node.id === hoveredId;
    const r = isHov ? RADIUS + 4 : RADIUS;

    /* outer glow ring */
    if (isHov) {
      ctx.beginPath();
      ctx.arc(nx, ny, r + 8, 0, Math.PI * 2);
      const glowGrad = ctx.createRadialGradient(nx, ny, r, nx, ny, r + 12);
      glowGrad.addColorStop(0, color + '40');
      glowGrad.addColorStop(1, color + '00');
      ctx.fillStyle = glowGrad;
      ctx.fill();
    }

    /* node body */
    const bodyGrad = ctx.createRadialGradient(nx - r * 0.3, ny - r * 0.3, 0, nx, ny, r);
    bodyGrad.addColorStop(0, color + 'cc');
    bodyGrad.addColorStop(0.5, color + '66');
    bodyGrad.addColorStop(1, color + '22');
    ctx.beginPath();
    ctx.arc(nx, ny, r, 0, Math.PI * 2);
    ctx.fillStyle = bodyGrad;
    ctx.fill();

    /* border */
    ctx.strokeStyle = color;
    ctx.lineWidth = isHov ? 2.5 : 1.5;
    ctx.shadowColor = color;
    ctx.shadowBlur = isHov ? 20 : 8;
    ctx.stroke();
    ctx.shadowBlur = 0;

    /* risk arc */
    const startAngle = -Math.PI / 2;
    const arcAngle = (node.risk_score / 100) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(nx, ny, r + 5, startAngle, startAngle + arcAngle);
    ctx.strokeStyle = node.risk_score > 60 ? '#ff3040aa' : node.risk_score > 30 ? '#ffb700aa' : '#00ff88aa';
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.stroke();

    /* label */
    ctx.fillStyle = '#f0f8ff';
    ctx.font = `bold ${isHov ? 12 : 11}px "JetBrains Mono", monospace`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const short = node.label.length > 10 ? node.label.slice(0, 9) + '…' : node.label;
    ctx.fillText(short, nx, ny);

    /* type label below */
    ctx.fillStyle = color + 'aa';
    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.textBaseline = 'top';
    ctx.fillText(node.type.toUpperCase(), nx, ny + r + 6);

    /* hover tooltip */
    if (isHov) {
      const tw = 160, th = 56;
      const tx = Math.min(nx + r + 8, w - tw - 4);
      const ty = Math.max(ny - th / 2, 4);
      ctx.fillStyle = 'rgba(4,8,14,0.95)';
      ctx.strokeStyle = color + 'aa';
      ctx.lineWidth = 1;
      roundRect(ctx, tx, ty, tw, th, 8);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = '#f0f8ff';
      ctx.font = '11px "JetBrains Mono", monospace';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(node.label.slice(0, 20), tx + 10, ty + 8);
      ctx.fillStyle = color;
      ctx.font = '10px "JetBrains Mono", monospace';
      ctx.fillText(`Risk: ${node.risk_score}  Trust: ${node.trust_score}`, tx + 10, ty + 26);
      ctx.fillStyle = '#6a8aaa';
      ctx.fillText(node.type, tx + 10, ty + 40);
    }
  }
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}
