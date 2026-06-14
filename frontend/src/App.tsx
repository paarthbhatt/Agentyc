import { useEffect, useState } from 'react';
import {
  Agent, api, BehaviorBaseline, DashboardSummary, GraphResponse,
  Incident, MCPAssessment, RedTeamScenario, SandboxProfile,
  TelemetryEvent, ThreatIntel, ToolTrust as ToolTrustType,
} from './lib/api';
import { useAuth } from './context/AuthContext';
import { Login, Register } from './pages/Auth';

import Sidebar, { SectionId } from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';

import Overview    from './pages/Overview';
import Agents      from './pages/Agents';
import Incidents   from './pages/Incidents';
import Replay      from './pages/Replay';
import GraphView   from './pages/GraphView';
import Memory      from './pages/Memory';
import ToolTrust   from './pages/ToolTrust';
import Policies    from './pages/Policies';
import ThreatIntelPage from './pages/ThreatIntel';
import MCPSecurity from './pages/MCPSecurity';
import RedTeam     from './pages/RedTeam';
import Sandbox     from './pages/Sandbox';

const emptySummary: DashboardSummary = {
  active_agents: 0, global_risk_score: 0, ongoing_attacks: 0, blocked_actions: 0,
  prompt_injection_attempts: 0, memory_poisoning_alerts: 0, trust_violations: 0, identity_violations: 0,
};

/* ── OAuth callback handler ─────────────────────────────── */
function handleOAuthCallback() {
  const params = new URLSearchParams(window.location.search);
  const access_token = params.get('access_token');
  const refresh_token = params.get('refresh_token');
  if (access_token && refresh_token) {
    localStorage.setItem('auth', JSON.stringify({
      user: { id: '', email: '', is_active: true, created_at: new Date().toISOString() },
      org: { id: '', name: '', slug: '', created_at: new Date().toISOString() },
      tokens: { access_token, refresh_token },
    }));
    window.history.replaceState({}, '', window.location.pathname);
    window.location.reload();
  }
}

handleOAuthCallback();

/* ── Auth Screen ────────────────────────────────────────── */
function AuthScreen() {
  const [showReg, setShowReg] = useState(false);
  return (
    <div style={{ position: 'relative' }}>
      {showReg ? (
        <>
          <Register onSuccess={() => setShowReg(false)} />
          <button onClick={() => setShowReg(false)} style={{
            position: 'fixed', top: 20, right: 20, zIndex: 10, background: 'rgba(0,212,255,0.1)',
            border: '1px solid rgba(0,212,255,0.3)', color: 'var(--cyan)', padding: '8px 16px',
            borderRadius: 8, cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
          }}>← Back to Login</button>
        </>
      ) : (
        <>
          <Login onSuccess={() => window.location.reload()} />
          <button onClick={() => setShowReg(true)} style={{
            position: 'fixed', bottom: 20, right: 20, zIndex: 10, background: 'rgba(0,212,255,0.1)',
            border: '1px solid rgba(0,212,255,0.3)', color: 'var(--cyan)', padding: '8px 16px',
            borderRadius: 8, cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
          }}>Create Account</button>
        </>
      )}
    </div>
  );
}

/* ── Main App ───────────────────────────────────────────── */
export default function App() {
  const { isAuthenticated } = useAuth();
  const [section, setSection] = useState<SectionId>('overview');

  const [summary,        setSummary]        = useState<DashboardSummary>(emptySummary);
  const [agents,         setAgents]         = useState<Agent[]>([]);
  const [incidents,      setIncidents]      = useState<Incident[]>([]);
  const [tools,          setTools]          = useState<ToolTrustType[]>([]);
  const [events,         setEvents]         = useState<TelemetryEvent[]>([]);
  const [graph,          setGraph]          = useState<GraphResponse | null>(null);
  const [replay,         setReplay]         = useState<TelemetryEvent[]>([]);
  const [threatIntel,    setThreatIntel]    = useState<ThreatIntel[]>([]);
  const [mcpAssessments, setMcpAssessments] = useState<MCPAssessment[]>([]);
  const [sandboxProfiles,setSandboxProfiles]= useState<SandboxProfile[]>([]);
  const [redTeamScenarios,setRedTeamScenarios] = useState<RedTeamScenario[]>([]);
  const [baseline,       setBaseline]       = useState<BehaviorBaseline | null>(null);
  const [error,          setError]          = useState<string | null>(null);
  const [loading,        setLoading]        = useState(true);

  async function load() {
    try {
      setError(null);
      const [summaryData, agentData, incidentData, trustData, threatData, mcpData, sandboxData, redTeamData] = await Promise.all([
        api.summary(), api.agents(), api.incidents(), api.toolTrust(),
        api.threatIntel(), api.mcpAssessments(), api.sandboxProfiles(), api.redTeamScenarios(),
      ]);
      setSummary(summaryData); setAgents(agentData); setIncidents(incidentData);
      setTools(trustData); setThreatIntel(threatData); setMcpAssessments(mcpData);
      setSandboxProfiles(sandboxData); setRedTeamScenarios(redTeamData);

      const agent = agentData[0];
      if (agent) {
        const [eventData, graphData, baselineData] = await Promise.all([
          api.events(agent.id), api.graph(agent.id), api.baseline(agent.id),
        ]);
        setEvents(eventData); setGraph(graphData); setBaseline(baselineData);
      }
      const inc = incidentData[0];
      if (inc) { const rd = await api.replay(inc.id); setReplay(rd.timeline); }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!isAuthenticated()) return;
    void load();
    const id = window.setInterval(() => void load(), 10000);
    return () => window.clearInterval(id);
  }, [isAuthenticated()]);

  if (!isAuthenticated()) return <AuthScreen />;

  function renderSection() {
    switch (section) {
      case 'overview':  return <Overview summary={summary} agents={agents} incidents={incidents} events={events} />;
      case 'agents':    return <Agents agents={agents} />;
      case 'incidents': return <Incidents incidents={incidents} />;
      case 'replay':    return <Replay incidents={incidents} replay={replay} selectedIncident={incidents[0] ?? null} />;
      case 'graph':     return <GraphView graph={graph} />;
      case 'memory':    return <Memory events={events} incidents={incidents} />;
      case 'tools':     return <ToolTrust tools={tools} />;
      case 'policies':  return <Policies profiles={sandboxProfiles} />;
      case 'threats':   return <ThreatIntelPage threatIntel={threatIntel} />;
      case 'mcp':       return <MCPSecurity assessments={mcpAssessments} />;
      case 'redteam':   return <RedTeam scenarios={redTeamScenarios} />;
      case 'sandbox':   return <Sandbox profiles={sandboxProfiles} />;
    }
  }

  return (
    <div className="app-shell">
      <Sidebar active={section} onNav={setSection} incidentCount={incidents.length} />
      <div className="main-content">
        <TopBar section={section} onRefresh={() => void load()} />
        <div className="page-content">
          {error && (
            <div className="error-banner">
              ⚠ Backend error: {error}
              <button onClick={() => void load()} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>RETRY</button>
            </div>
          )}
          {loading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '20px 0', color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
              <div style={{ width: 16, height: 16, border: '2px solid var(--border-dim)', borderTopColor: 'var(--cyan)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
              LOADING TELEMETRY…
              <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
            </div>
          )}
          {!loading && renderSection()}
        </div>
      </div>
    </div>
  );
}
