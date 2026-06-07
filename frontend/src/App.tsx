import { useEffect, useMemo, useState } from "react";
import {
  Agent,
  api,
  BehaviorBaseline,
  DashboardSummary,
  GraphResponse,
  Incident,
  MCPAssessment,
  RedTeamScenario,
  SandboxProfile,
  TelemetryEvent,
  ThreatIntel,
  ToolTrust,
} from "./lib/api";
import { useAuth } from "./context/AuthContext";
import { Login, Register } from "./pages/Auth";

const emptySummary: DashboardSummary = {
  active_agents: 0,
  global_risk_score: 0,
  ongoing_attacks: 0,
  blocked_actions: 0,
  prompt_injection_attempts: 0,
  memory_poisoning_alerts: 0,
  trust_violations: 0,
  identity_violations: 0,
};

function severityClass(value: string): string {
  if (value === "critical") return "critical";
  if (value === "high") return "high";
  if (value === "medium") return "medium";
  return "low";
}

function scoreClass(score: number, inverted = false): string {
  const bad = inverted ? score < 35 : score >= 75;
  const warn = inverted ? score < 60 : score >= 50;
  if (bad) return "critical";
  if (warn) return "high";
  return "low";
}

function Kpi({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: string;
}) {
  return (
    <div className={`kpi ${tone ?? ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function RiskBar({
  score,
  inverted = false,
}: {
  score: number;
  inverted?: boolean;
}) {
  return (
    <div className="riskbar">
      <div
        className={`riskbar-fill ${scoreClass(score, inverted)}`}
        style={{ width: `${Math.max(4, Math.min(100, score))}%` }}
      />
      <span>{score}</span>
    </div>
  );
}

function SecurityGraph({ graph }: { graph: GraphResponse | null }) {
  if (!graph) return <div className="empty">No graph loaded</div>;
  const nodes = graph.nodes.slice(0, 12);
  return (
    <div className="graph-grid">
      {nodes.map((node, index) => (
        <div
          key={node.id}
          className={`graph-node ${node.type}`}
          style={{ marginLeft: `${(index % 3) * 18}px` }}
        >
          <div>{node.label}</div>
          <small>
            {node.type} · R{node.risk_score} · T{node.trust_score}
          </small>
        </div>
      ))}
    </div>
  );
}

function App() {
  const { isAuthenticated, tokens, logout } = useAuth();
  const [showRegister, setShowRegister] = useState(false);
  const [summary, setSummary] = useState<DashboardSummary>(emptySummary);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [tools, setTools] = useState<ToolTrust[]>([]);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [replay, setReplay] = useState<TelemetryEvent[]>([]);
  const [threatIntel, setThreatIntel] = useState<ThreatIntel[]>([]);
  const [mcpAssessments, setMcpAssessments] = useState<MCPAssessment[]>([]);
  const [sandboxProfiles, setSandboxProfiles] = useState<SandboxProfile[]>([]);
  const [redTeamScenarios, setRedTeamScenarios] = useState<RedTeamScenario[]>(
    [],
  );
  const [baseline, setBaseline] = useState<BehaviorBaseline | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedAgent = agents[0];
  const selectedIncident = incidents[0];

  async function load() {
    try {
      setError(null);
      const [
        summaryData,
        agentData,
        incidentData,
        trustData,
        threatData,
        mcpData,
        sandboxData,
        redTeamData,
      ] = await Promise.all([
        api.summary(),
        api.agents(),
        api.incidents(),
        api.toolTrust(),
        api.threatIntel(),
        api.mcpAssessments(),
        api.sandboxProfiles(),
        api.redTeamScenarios(),
      ]);
      setSummary(summaryData);
      setAgents(agentData);
      setIncidents(incidentData);
      setTools(trustData);
      setThreatIntel(threatData);
      setMcpAssessments(mcpData);
      setSandboxProfiles(sandboxData);
      setRedTeamScenarios(redTeamData);
      const agent = agentData[0];
      if (agent) {
        const [eventData, graphData, baselineData] = await Promise.all([
          api.events(agent.id),
          api.graph(agent.id),
          api.baseline(agent.id),
        ]);
        setEvents(eventData);
        setGraph(graphData);
        setBaseline(baselineData);
      }
      const incident = incidentData[0];
      if (incident) {
        const replayData = await api.replay(incident.id);
        setReplay(replayData.timeline);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown dashboard error");
    }
  }

  useEffect(() => {
    void load();
    const interval = window.setInterval(() => void load(), 8000);
    return () => window.clearInterval(interval);
  }, []);

  const topRiskAgents = useMemo(
    () => [...agents].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5),
    [agents],
  );
  const intentMatchScore = selectedIncident?.evidence?.intent_match_score;
  const intentMatchDisplay =
    typeof intentMatchScore === "number" || typeof intentMatchScore === "string"
      ? String(intentMatchScore)
      : "—";

  return (
    <>
      {!isAuthenticated() ? (
        <>
          {showRegister ? (
            <div>
              <Register onSuccess={() => setShowRegister(false)} />
              <button onClick={() => setShowRegister(false)} style={{ position: 'absolute', top: 20, right: 20, zIndex: 10 }}>
                Back to Login
              </button>
            </div>
          ) : (
            <div>
              <Login onSuccess={() => window.location.reload()} />
              <button onClick={() => setShowRegister(true)} style={{ position: 'absolute', bottom: 20, right: 20, zIndex: 10, background: 'rgba(59, 130, 246, 0.2)', border: '1px solid rgba(59, 130, 246, 0.5)', color: '#3b82f6', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer' }}>
                Create Account
              </button>
            </div>
          )}
        </>
      ) : (
        <main className="shell">
          <aside className="sidebar">
            <div className="brand">
          <div className="logo">AS</div>
          <div>
            <h1>Agent Sentinel</h1>
            <p>Trust Nothing. Verify Every Thought.</p>
          </div>
        </div>
        <nav>
          {[
            "Overview",
            "Agents",
            "Incidents",
            "Replay",
            "Security Graph",
            "Memory",
            "Tool Trust",
            "Policies",
            "Threat Intel",
            "MCP Security",
            "Red Team",
            "Sandbox",
          ].map((item) => (
            <a key={item} className={item === "Overview" ? "active" : ""}>
              {item}
            </a>
          ))}
        </nav>
      </aside>

      <section className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Runtime Agent Security Operations</p>
            <h2>Primary SOC Dashboard</h2>
          </div>
          <button onClick={() => void load()}>Refresh telemetry</button>
        </header>

        {error && (
          <div className="banner">Backend connection issue: {error}</div>
        )}

        <section
          className="command-center"
          aria-label="Agent Sentinel command center status"
        >
          <div>
            <p className="eyebrow">Zero Trust Agent Runtime</p>
            <h3>
              Continuous verification across identity, intent, tools, memory,
              MCP, and delegation paths.
            </h3>
          </div>
          <div className="status-strip">
            <span>
              <b>EDR</b> active
            </span>
            <span>
              <b>Firewall</b> enforcing
            </span>
            <span>
              <b>MCP</b> monitored
            </span>
            <span>
              <b>Replay</b> recording
            </span>
          </div>
        </section>

        <section className="kpi-grid">
          <Kpi label="Active agents" value={summary.active_agents} />
          <Kpi
            label="Global risk"
            value={summary.global_risk_score}
            tone={scoreClass(summary.global_risk_score)}
          />
          <Kpi
            label="Ongoing attacks"
            value={summary.ongoing_attacks}
            tone="critical"
          />
          <Kpi
            label="Blocked actions"
            value={summary.blocked_actions}
            tone="high"
          />
          <Kpi
            label="Prompt injection"
            value={summary.prompt_injection_attempts}
            tone="high"
          />
          <Kpi
            label="Memory poisoning"
            value={summary.memory_poisoning_alerts}
            tone="high"
          />
          <Kpi label="Trust violations" value={summary.trust_violations} />
          <Kpi
            label="Identity violations"
            value={summary.identity_violations}
            tone="critical"
          />
        </section>

        <section className="grid two">
          <article className="panel wide">
            <div className="panel-head">
              <h3>Live attack timeline</h3>
              <span>
                {selectedAgent ? selectedAgent.name : "No agent selected"}
              </span>
            </div>
            <div className="timeline">
              {events.map((event) => (
                <div className="timeline-row" key={event.id}>
                  <span className={`dot ${severityClass(event.severity)}`} />
                  <div>
                    <strong>{event.event_type}</strong>
                    <p>{JSON.stringify(event.payload).slice(0, 180)}</p>
                  </div>
                  <RiskBar score={event.risk_score} />
                </div>
              ))}
            </div>
          </article>

          <article className="panel">
            <div className="panel-head">
              <h3>Agent risk leaderboard</h3>
            </div>
            {topRiskAgents.map((agent) => (
              <div className="metric-row" key={agent.id}>
                <div>
                  <strong>{agent.name}</strong>
                  <p>
                    {agent.framework} · {agent.status}
                  </p>
                </div>
                <RiskBar score={agent.risk_score} />
              </div>
            ))}
          </article>
        </section>

        <section className="grid three">
          <article className="panel">
            <div className="panel-head">
              <h3>Incident queue</h3>
            </div>
            {incidents.slice(0, 6).map((incident) => (
              <div className="incident" key={incident.id}>
                <span className={`pill ${severityClass(incident.severity)}`}>
                  {incident.severity}
                </span>
                <strong>{incident.title}</strong>
                <p>{incident.root_cause}</p>
              </div>
            ))}
          </article>

          <article className="panel">
            <div className="panel-head">
              <h3>Tool trust heatmap</h3>
            </div>
            {tools.map((tool) => (
              <div className="metric-row" key={tool.id}>
                <div>
                  <strong>{tool.name}</strong>
                  <p>
                    {tool.type} · {tool.status}
                  </p>
                </div>
                <RiskBar score={tool.trust_score} inverted />
              </div>
            ))}
          </article>

          <article className="panel">
            <div className="panel-head">
              <h3>Security graph preview</h3>
            </div>
            <SecurityGraph graph={graph} />
          </article>
        </section>

        <section className="grid three">
          <article className="panel">
            <div className="panel-head">
              <h3>MCP security assessments</h3>
            </div>
            {mcpAssessments.slice(0, 5).map((assessment) => (
              <div className="incident" key={assessment.id}>
                <span
                  className={`pill ${assessment.verdict === "blocked" ? "critical" : assessment.verdict === "suspicious" ? "high" : "low"}`}
                >
                  {assessment.verdict}
                </span>
                <strong>
                  {assessment.server_name} / {assessment.tool_name}
                </strong>
                <p>
                  Risk {assessment.risk_score} · Trust {assessment.trust_score}{" "}
                  · {assessment.findings.slice(0, 2).join(", ")}
                </p>
              </div>
            ))}
          </article>

          <article className="panel">
            <div className="panel-head">
              <h3>Threat intelligence</h3>
            </div>
            {threatIntel.slice(0, 6).map((indicator) => (
              <div className="incident" key={indicator.id}>
                <span className={`pill ${severityClass(indicator.severity)}`}>
                  {indicator.severity}
                </span>
                <strong>{indicator.indicator_type}</strong>
                <p>
                  {indicator.value} · confidence {indicator.confidence}
                </p>
              </div>
            ))}
          </article>

          <article className="panel">
            <div className="panel-head">
              <h3>Behavioral baseline</h3>
            </div>
            {baseline ? (
              <div className="callout compact">
                <p className="eyebrow">Adaptive anomaly model</p>
                <strong className="medium-score">{baseline.last_score}</strong>
                <p>
                  {baseline.event_count} events learned ·{" "}
                  {baseline.anomaly_count} anomalies · tools:{" "}
                  {baseline.normal_tools.slice(0, 4).join(", ")}
                </p>
              </div>
            ) : (
              <div className="empty">No baseline yet</div>
            )}
          </article>
        </section>

        <section className="grid three">
          <article className="panel">
            <div className="panel-head">
              <h3>White-box red team</h3>
            </div>
            {redTeamScenarios.slice(0, 4).map((scenario) => (
              <div className="incident" key={scenario.id}>
                <span className={`pill ${severityClass(scenario.severity)}`}>
                  {scenario.severity}
                </span>
                <strong>{scenario.name}</strong>
                <p>
                  {scenario.category} · controls:{" "}
                  {scenario.expected_controls.slice(0, 3).join(", ")}
                </p>
              </div>
            ))}
          </article>

          <article className="panel">
            <div className="panel-head">
              <h3>Sandbox profiles</h3>
            </div>
            {sandboxProfiles.slice(0, 4).map((profile) => (
              <div className="metric-row" key={profile.id}>
                <div>
                  <strong>{profile.name}</strong>
                  <p>
                    {profile.runtime} · net {profile.network_policy} · shell{" "}
                    {profile.shell_policy}
                  </p>
                </div>
              </div>
            ))}
          </article>

          <article className="panel">
            <div className="panel-head">
              <h3>Multi-agent security</h3>
            </div>
            <div className="callout compact">
              <p className="eyebrow">Swarm control plane</p>
              <h3>Trust inheritance and delegation risk</h3>
              <p>
                Delegations are scored for trust laundering, cross-environment
                transfer, privilege inheritance, and malicious task handoff
                before downstream agents act.
              </p>
            </div>
          </article>
        </section>

        <section className="grid two">
          <article className="panel">
            <div className="panel-head">
              <h3>Attack replay</h3>
              <span>{selectedIncident?.session_id ?? "No incident"}</span>
            </div>
            <div className="replay">
              {replay.map((event, index) => (
                <div className="replay-step" key={event.id}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <div>
                    <strong>{event.event_type}</strong>
                    <p>
                      Risk {event.risk_score} · Trust {event.trust_score} ·{" "}
                      {new Date(event.occurred_at).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </article>

          <article className="panel">
            <div className="panel-head">
              <h3>Cognitive firewall focus</h3>
            </div>
            <div className="callout">
              <p className="eyebrow">Flagship control</p>
              <h3>Intent Match Score</h3>
              <strong className="hero-score">{intentMatchDisplay}</strong>
              <p>
                The firewall compares the approved user goal against the actual
                tool, action, resource, identity permissions, memory influence,
                and trust chain before execution.
              </p>
            </div>
          </article>
        </section>
      </section>
    </main>
      )}
    </>
  );
}

export default App;
