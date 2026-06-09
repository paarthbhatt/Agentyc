export type Agent = {
  id: string;
  name: string;
  framework: string;
  owner: string;
  environment: string;
  status: string;
  risk_score: number;
  trust_level: number;
  created_at: string;
};

export type Incident = {
  id: string;
  agent_id: string;
  session_id: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  root_cause: string;
  evidence: Record<string, unknown>;
  response_actions: string[];
  created_at: string;
  updated_at: string;
};

export type TelemetryEvent = {
  id: string;
  agent_id: string;
  session_id: string;
  event_type: string;
  severity: string;
  payload: Record<string, unknown>;
  trust_score: number;
  risk_score: number;
  occurred_at: string;
};

export type ToolTrust = {
  id: string;
  name: string;
  type: string;
  trust_score: number;
  status: string;
  incident_count: number;
};

export type DashboardSummary = {
  active_agents: number;
  global_risk_score: number;
  ongoing_attacks: number;
  blocked_actions: number;
  prompt_injection_attempts: number;
  memory_poisoning_alerts: number;
  trust_violations: number;
  identity_violations: number;
};

export type GraphResponse = {
  nodes: {
    id: string;
    label: string;
    type: string;
    risk_score: number;
    trust_score: number;
  }[];
  edges: { id: string; source: string; target: string; label: string }[];
};

export type ThreatIntel = {
  id: string;
  indicator_type: string;
  value: string;
  severity: string;
  confidence: number;
  source: string;
  tags: string[];
  active: boolean;
  created_at: string;
};

export type MCPAssessment = {
  id: string;
  server_name: string;
  tool_name: string;
  risk_score: number;
  trust_score: number;
  verdict: string;
  findings: string[];
  created_at: string;
};

export type SandboxProfile = {
  id: string;
  name: string;
  runtime: string;
  network_policy: string;
  filesystem_policy: string;
  shell_policy: string;
  database_policy: string;
  allowed_hosts: string[];
  created_at: string;
};

export type RedTeamScenario = {
  id: string;
  name: string;
  category: string;
  attack_steps: string[];
  expected_controls: string[];
  severity: string;
  status: string;
  created_at: string;
};

export type BehaviorBaseline = {
  id: string;
  agent_id: string;
  normal_tools: string[];
  normal_actions: string[];
  normal_resources: string[];
  event_count: number;
  anomaly_count: number;
  last_score: number;
  updated_at: string;
};

export const API_BASE =
  import.meta.env.VITE_API_BASE ?? "http://localhost:8000/api/v1";

async function request<T>(path: string): Promise<T> {
  const auth = localStorage.getItem('auth');
  const headers: Record<string, string> = {};
  
  if (auth) {
    try {
      const parsed = JSON.parse(auth);
      if (parsed.tokens?.access_token) {
        headers['Authorization'] = `Bearer ${parsed.tokens.access_token}`;
      }
    } catch {
      // Ignore parse errors
    }
  }
  
  const response = await fetch(`${API_BASE}${path}`, { headers });
  if (!response.ok) {
    if (response.status === 401) {
      localStorage.removeItem('auth');
      window.location.href = '/';
    }
    throw new Error(`API ${response.status}: ${await response.text()}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  summary: () => request<DashboardSummary>("/dashboard/summary"),
  agents: () => request<Agent[]>("/agents"),
  incidents: () => request<Incident[]>("/incidents"),
  agentRisk: () =>
    request<
      {
        id: string;
        name: string;
        risk_score: number;
        trust_level: number;
        status: string;
      }[]
    >("/risk/agents"),
  toolTrust: () => request<ToolTrust[]>("/trust/tools"),
  events: (agentId: string) =>
    request<TelemetryEvent[]>(`/agents/${agentId}/events?limit=20`),
  graph: (agentId: string) =>
    request<GraphResponse>(`/graph/agents/${agentId}`),
  replay: (incidentId: string) =>
    request<{ incident: Incident; timeline: TelemetryEvent[] }>(
      `/replay/incidents/${incidentId}`,
    ),
  threatIntel: () => request<ThreatIntel[]>("/threats/indicators?active=true"),
  mcpAssessments: () => request<MCPAssessment[]>("/mcp/assessments"),
  sandboxProfiles: () => request<SandboxProfile[]>("/sandbox/profiles"),
  redTeamScenarios: () => request<RedTeamScenario[]>("/redteam/scenarios"),
  baseline: (agentId: string) =>
    request<BehaviorBaseline>(`/baselines/agents/${agentId}`),
};
