import { useMemo, useState } from "react";
import { Link } from "wouter";
import ThreatRing from "../components/ui/ThreatRing";
import type { Agent } from "../lib/api";

type FilterEnv = "all" | string;

function sev(s: number) {
  if (s >= 75) return "critical";
  if (s >= 50) return "high";
  return "good";
}

interface Props {
  agents: Agent[];
}

export default function Agents({ agents }: Props) {
  const envs = useMemo(
    () => ["all", ...Array.from(new Set(agents.map((a) => a.environment)))],
    [agents],
  );
  const [envFilter, setEnvFilter] = useState<FilterEnv>("all");

  // Sort by risk descending to present the leaderboard
  const sorted = useMemo(() => {
    const copy = [...agents];
    if (envFilter !== "all") copy.filter((a) => a.environment === envFilter);
    return copy.sort((a, b) => b.risk_score - a.risk_score);
  }, [agents, envFilter]);

  const displayed =
    envFilter === "all"
      ? sorted
      : sorted.filter((a) => a.environment === envFilter);

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Agent Fleet Management</div>
          <div className="page-title">Registered Agents</div>
          <div className="page-sub">
            {agents.length} agents monitored across all environments
          </div>
        </div>
        <span className={`badge ${agents.length > 0 ? "info" : "low"}`}>
          {agents.length} TOTAL
        </span>
      </div>

      {/* Filter chips */}
      <div
        style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}
      >
        {envs.map((env) => (
          <button
            key={env}
            onClick={() => setEnvFilter(env)}
            style={{
              padding: "6px 14px",
              borderRadius: 999,
              fontSize: 11,
              fontFamily: "'JetBrains Mono', monospace",
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              cursor: "pointer",
              background:
                envFilter === env ? "rgba(0,212,255,0.1)" : "transparent",
              border:
                envFilter === env
                  ? "1px solid rgba(0,212,255,0.3)"
                  : "1px solid var(--border-subtle)",
              color: envFilter === env ? "var(--cyan)" : "var(--text-muted)",
              transition: "all 160ms ease",
            }}
          >
            {env}
          </button>
        ))}
      </div>

      {displayed.length === 0 ? (
        <div className="glass-card">
          <div className="card-body">
            <div className="empty-state">
              <div className="empty-icon">◈</div>No agents
            </div>
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {/* Leaderboard summary */}
          <div className="glass-card" style={{ padding: "14px 20px" }}>
            <div
              style={{
                fontSize: 10,
                color: "var(--text-dim)",
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: "0.1em",
                textTransform: "uppercase",
                marginBottom: 10,
              }}
            >
              Risk Leaderboard
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {sorted.slice(0, 6).map((a) => {
                const color =
                  a.risk_score >= 75
                    ? "var(--red)"
                    : a.risk_score >= 50
                      ? "var(--amber)"
                      : "var(--green)";
                return (
                  <div
                    key={a.id}
                    style={{ display: "flex", alignItems: "center", gap: 12 }}
                  >
                    <div
                      style={{
                        position: "relative",
                        width: 8,
                        height: 8,
                        flexShrink: 0,
                      }}
                    >
                      <div
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: "50%",
                          background:
                            a.status === "active"
                              ? "var(--green)"
                              : "var(--text-dim)",
                          boxShadow:
                            a.status === "active"
                              ? "0 0 6px var(--green)"
                              : "none",
                        }}
                      />
                    </div>
                    <Link
                      href={`/agents/${a.id}`}
                      style={{
                        flex: 1,
                        minWidth: 0,
                        fontSize: 13,
                        fontWeight: 600,
                        color: "var(--text-primary)",
                        textDecoration: "none",
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        transition: "color 160ms ease",
                      }}
                      onMouseEnter={(e) =>
                        (e.currentTarget.style.color = "var(--cyan)")
                      }
                      onMouseLeave={(e) =>
                        (e.currentTarget.style.color = "var(--text-primary)")
                      }
                    >
                      {a.name}
                    </Link>
                    <div
                      style={{
                        fontSize: 10,
                        color: "var(--text-dim)",
                        fontFamily: "'JetBrains Mono', monospace",
                        width: 100,
                        flexShrink: 0,
                      }}
                    >
                      {a.framework} · {a.environment}
                    </div>
                    <div
                      className="risk-bar-wrap"
                      style={{ width: 100, flexShrink: 0 }}
                    >
                      <div className="risk-bar-track">
                        <div
                          className={`risk-bar-fill ${a.risk_score >= 75 ? "critical" : a.risk_score >= 50 ? "high" : "low"}`}
                          style={{ width: `${a.risk_score}%` }}
                        />
                      </div>
                      <span className="risk-bar-label" style={{ color }}>
                        {a.risk_score}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Detail cards */}
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {displayed.map((agent) => {
              const sevClass =
                sev(agent.risk_score) === "critical"
                  ? "red"
                  : sev(agent.risk_score) === "high"
                    ? "amber"
                    : "cyan";
              return (
                <Link
                  key={agent.id}
                  href={`/agents/${agent.id}`}
                  className={`glass-card glow-${sevClass}`}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 20,
                    padding: "16px 20px",
                    textDecoration: "none",
                    cursor: "pointer",
                    transition: "transform 120ms ease, box-shadow 180ms ease",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.transform = "translateX(4px)";
                    e.currentTarget.style.boxShadow =
                      "0 0 20px var(--border-dim)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.transform = "none";
                    e.currentTarget.style.boxShadow = "";
                  }}
                >
                  {/* Status orb */}
                  <div
                    style={{
                      position: "relative",
                      width: 40,
                      height: 40,
                      flexShrink: 0,
                    }}
                  >
                    <div
                      style={{
                        position: "absolute",
                        inset: "50%",
                        transform: "translate(-50%,-50%)",
                        width: 10,
                        height: 10,
                        borderRadius: "50%",
                        background:
                          agent.status === "active"
                            ? "var(--green)"
                            : "var(--text-dim)",
                        boxShadow:
                          agent.status === "active"
                            ? "0 0 8px var(--green)"
                            : "none",
                      }}
                    />
                    {agent.status === "active" && (
                      <>
                        {[1, 2].map((r) => (
                          <div
                            key={r}
                            style={{
                              position: "absolute",
                              inset: `calc(50% - ${r * 8}px)`,
                              borderRadius: "50%",
                              border: "1px solid var(--green)",
                              animation: `orb-ring ${1.5 + r * 0.5}s ease-in-out infinite`,
                              animationDelay: `${r * 0.3}s`,
                            }}
                          />
                        ))}
                      </>
                    )}
                  </div>

                  {/* Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        marginBottom: 6,
                        flexWrap: "wrap",
                      }}
                    >
                      <span
                        style={{
                          fontSize: 16,
                          fontWeight: 700,
                          color: "var(--text-bright)",
                        }}
                      >
                        {agent.name}
                      </span>
                      <span
                        className={`badge ${agent.status === "active" ? "low" : "medium"}`}
                      >
                        {agent.status}
                      </span>
                    </div>
                    <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
                      {[
                        ["Framework", agent.framework],
                        ["Owner", agent.owner],
                        ["Env", agent.environment],
                        [
                          "Registered",
                          new Date(agent.created_at).toLocaleDateString(),
                        ],
                      ].map(([k, v]) => (
                        <div key={k}>
                          <div
                            style={{
                              fontSize: 9,
                              color: "var(--text-dim)",
                              fontFamily: "'JetBrains Mono', monospace",
                              letterSpacing: "0.1em",
                              textTransform: "uppercase",
                            }}
                          >
                            {k}
                          </div>
                          <div
                            style={{
                              fontSize: 12,
                              color: "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                              marginTop: 2,
                            }}
                          >
                            {v}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Risk ring */}
                  <ThreatRing score={agent.risk_score} size={90} label="Risk" />

                  {/* Trust ring */}
                  <ThreatRing
                    score={agent.trust_level}
                    size={90}
                    label="Trust"
                    color={
                      agent.trust_level < 40
                        ? "#ff3040"
                        : agent.trust_level < 70
                          ? "#ffb700"
                          : "#00ff88"
                    }
                  />

                  {/* ID */}
                  <div
                    style={{
                      fontSize: 10,
                      color: "var(--text-dim)",
                      fontFamily: "'JetBrains Mono', monospace",
                      maxWidth: 120,
                      wordBreak: "break-all",
                      flexShrink: 0,
                    }}
                  >
                    {agent.id.slice(0, 8)}…
                  </div>
                </Link>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
