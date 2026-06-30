import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";

export interface Props {
  section?: string;
  onRefresh?: () => void;
}

const SECTION_META: Record<string, { eyebrow: string; title: string }> = {
  "/": {
    eyebrow: "Runtime AI Security Operations",
    title: "Primary SOC Dashboard",
  },
  "/agents": { eyebrow: "Agent Fleet Management", title: "Registered Agents" },
  "/incidents": { eyebrow: "Security Incident Queue", title: "Active Incidents" },
  "/replay": { eyebrow: "Forensic Reconstruction", title: "Attack Replay" },
  "/graph": { eyebrow: "Topology Visualisation", title: "Security Graph" },
  "/memory": {
    eyebrow: "Memory & Context Security",
    title: "Agent Memory Objects",
  },
  "/tools": { eyebrow: "Tool Trust Analysis", title: "Tool Trust Heatmap" },
  "/policies": { eyebrow: "Enforcement Policies", title: "Policy Manager" },
  "/threats": { eyebrow: "Threat Intelligence Feed", title: "Threat Indicators" },
  "/mcp": { eyebrow: "Model Context Protocol", title: "MCP Security Assessments" },
  "/redteam": { eyebrow: "Adversarial Testing", title: "Red Team Scenarios" },
  "/sandbox": { eyebrow: "Execution Containment", title: "Sandbox Profiles" },
};

function resolveMeta(pathname: string) {
  if (pathname.startsWith("/agents/"))
    return { eyebrow: "Agent Deep-Dive", title: "Agent Detail" };
  const key = pathname.replace(/\/$/, "") || "/";
  return SECTION_META[key] ?? { eyebrow: "Agent Sentinel", title: pathname };
}

export default function TopBar({ onRefresh }: Props) {
  const location = useLocation();
  const meta = resolveMeta(location.pathname);
  const [clock, setClock] = useState("");

  useEffect(() => {
    function tick() {
      const now = new Date();
      const h = String(now.getHours()).padStart(2, "0");
      const m = String(now.getMinutes()).padStart(2, "0");
      const s = String(now.getSeconds()).padStart(2, "0");
      const ms = String(now.getMilliseconds()).padStart(3, "0");
      setClock(`${h}:${m}:${s}.${ms}`);
    }
    tick();
    const id = setInterval(tick, 50);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-left">
        <div className="topbar-eyebrow">{meta.eyebrow}</div>
        <div className="topbar-title">{meta.title}</div>
      </div>
      <div className="topbar-right">
        <div className="topbar-status">
          <span className="status-dot" />
          SYSTEMS NOMINAL
        </div>
        <div className="topbar-clock">{clock}</div>
        {onRefresh && (
          <button className="topbar-refresh" onClick={onRefresh}>
            ↻ REFRESH
          </button>
        )}
      </div>
    </header>
  );
}
