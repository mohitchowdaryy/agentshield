// Typed client for the AgentShield API. All security logic lives in the backend; this only fetches and displays.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Outcome = "succeeded" | "failed" | "inconclusive" | "errored";

export interface Finding {
  id: string;
  fingerprint: string;
  rule_id: string;
  title: string;
  severity: Severity;
  status: "open" | "resolved";
  source: "live" | "demo";
  account_id: string;
  region: string;
  resource_arn: string;
  resource_type: string;
  risk_type: string;
  exploitability: string;
  remediation: string;
  first_seen_at: string;
  last_seen_at: string;
  last_scan_id: string | null;
  evidence?: Record<string, unknown>;
  references?: string[];
  observations?: { scan_id: string; observed_at: string }[];
  correlations?: string[];
}

export interface CollectionGap {
  service: string;
  operation: string;
  resource: string | null;
  region: string | null;
  error_code: string;
  message: string;
}

export interface Scan {
  id: string;
  source: "live" | "demo";
  status: string;
  account_id: string | null;
  caller_arn: string | null;
  regions: string[];
  collection_gaps: CollectionGap[];
  summary: { findings?: number; by_severity?: Record<string, number>; resources?: number; resolved?: number };
  error: string | null;
  started_at: string;
  finished_at: string | null;
  findings?: Finding[];
}

export interface Resource {
  id: string;
  arn: string;
  type: string;
  name: string;
  region: string;
  last_seen_at: string;
}

export interface Checks {
  saw_malicious_content: boolean;
  unsafe_tool_call_proposed: boolean;
  unsafe_calls_denied_by_gateway: number;
  unsafe_calls_allowed_by_gateway: number;
  simulated_violation_executed: boolean;
  legitimate_task_completed: boolean;
  run_status: string;
}

export interface RunSummary {
  id: string;
  batch_id: string | null;
  scenario_id: string;
  scenario_name: string;
  category: string | null;
  agent_id: string;
  policy_mode: "protected" | "vulnerable";
  provider: string;
  model: string;
  is_simulated: boolean;
  status: string;
  outcome: Outcome;
  defense_layer: string | null;
  checks: Checks;
  usage: { input_tokens?: number; output_tokens?: number; cost_usd?: number | null; model_calls?: number; estimated?: boolean };
  trial_set_id?: string | null;
  trial_index?: number | null;
  started_at: string;
  finished_at: string | null;
}

export interface TrialSet {
  id: string;
  scenario_id: string;
  scenario_name: string;
  policy_mode: "protected" | "vulnerable";
  provider: string;
  model: string;
  is_simulated: boolean;
  trials: number;
  outcome_counts: Record<string, number>;
  check_counts: Record<string, number>;
  run_ids: string[];
  created_at: string;
  finished_at: string | null;
}

export interface Decision {
  decision: "allow" | "deny";
  rule_ids: string[];
  reasons: string[];
  approval: string;
  policy_mode: string;
}

export interface ToolCall {
  id: string;
  seq: number;
  turn: number;
  tool: string;
  arguments: Record<string, unknown>;
  untrusted_context: boolean;
  executed: boolean;
  result: Record<string, unknown> | null;
  error: string | null;
  proposed_at: string;
  executed_at: string | null;
  decision: Decision | null;
}

export interface EvidenceEvent {
  seq: number;
  type: string;
  trust: string | null;
  payload: Record<string, unknown>;
  at: string;
}

export interface ViolationCondition {
  id: string;
  kind: string;
  description: string;
}

export interface ScenarioDefinition {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  objective: string;
  legitimate_task: string;
  user_message: string;
  entry_point: string;
  entry_point_detail: string;
  payload: string;
  expected_behavior: string;
  violation_conditions: ViolationCondition[];
  task_completion_markers: string[];
  mappings: { owasp_llm: string[]; mitre_atlas: string[]; other: string[] };
}

export interface Scenario {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  version: number;
  definition: ScenarioDefinition;
  updated_at: string;
}

export interface RunDetail extends RunSummary {
  scenario: ScenarioDefinition | null;
  evaluation: {
    outcome: Outcome;
    defense_layer: string;
    rationale: string;
    checks: Checks;
    unsafe_proposals: Record<string, unknown>[];
    violations: Record<string, unknown>[];
    outbox?: { destination: string; subject: string; body: string; delivered: boolean; simulated: boolean }[];
  };
  final_answer: string | null;
  error: string | null;
  interactions: {
    id: string;
    turn: number;
    request: Record<string, unknown>;
    response: Record<string, unknown>;
    input_tokens: number | null;
    output_tokens: number | null;
    cost_usd: number | null;
    latency_ms: number | null;
  }[];
  tool_calls: ToolCall[];
  events: EvidenceEvent[];
}

export interface ToolCallRow {
  id: string;
  run_id: string;
  scenario_id: string;
  policy_mode: string;
  provider: string;
  is_simulated: boolean;
  seq: number;
  turn: number;
  tool: string;
  arguments: Record<string, unknown>;
  untrusted_context: boolean;
  executed: boolean;
  decision: "allow" | "deny" | null;
  rule_ids: string[];
  reasons: string[];
  approval: string | null;
  proposed_at: string;
}

export interface PathNode {
  id: string;
  type: "entry" | "agent" | "identity" | "resource";
  label: string;
  arn?: string;
}

export interface PathEdge {
  source: string;
  target: string;
  label: string;
  status: "observed_in_simulation" | "modeled" | "configured";
}

export interface Correlation {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  status: "modeled" | "agent_step_observed_in_simulation";
  agent_id: string;
  finding_ids: string[];
  run_ids: string[];
  evidence: Record<string, unknown>;
  path: { nodes: PathNode[]; edges: PathEdge[] };
  explanation: string;
  updated_at: string;
}

export interface Overview {
  findings: {
    open: number;
    resolved: number;
    by_severity: Record<string, number>;
    by_source: Record<string, number>;
    by_rule: Record<string, number>;
  };
  scans: { total: number; last: Scan | null };
  resources: number;
  observations: number;
  redteam: {
    runs: number;
    simulated_runs: number;
    live_model_runs: number;
    by_outcome: Record<string, number>;
    by_mode_outcome: Record<string, Record<string, number>>;
    scenarios: number;
  };
  gateway: {
    tool_call_attempts: number;
    allowed: number;
    denied: number;
    executed: number;
    denials_by_rule: Record<string, number>;
  };
  correlations: { total: number; by_status: Record<string, number> };
}

export interface SettingsView {
  version: string;
  database: string;
  bind: string;
  cors_origins: string[];
  api_token_required: boolean;
  max_request_bytes: number;
  agent: { max_turns: number; timeout_s: number; max_retries: number };
  integrations: {
    simulator: { available: boolean; note: string };
    anthropic: { configured: boolean; model: string };
    ollama: { base_url: string; model: string; note: string };
    aws: { profile: string | null; regions: string[]; note: string };
  };
}

export interface Agent {
  id: string;
  name: string;
  description: string;
  cloud_identity_arn: string | null;
  profile: Record<string, unknown>;
}

const TOKEN_KEY = "agentshield.apiToken";

export function getToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setToken(token: string): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: token simply is not remembered */
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const token = getToken();
  if (token && method === "POST") headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, `${res.status}: ${detail}`);
  }
  return (await res.json()) as T;
}

export const api = {
  get: <T,>(path: string) => request<T>("GET", path),
  post: <T,>(path: string, body: unknown = {}) => request<T>("POST", path, body),
};

export function qs(params: Record<string, string | string[] | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
    else sp.set(k, v);
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}
