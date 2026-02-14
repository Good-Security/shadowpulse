const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function fetchAPI<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  // Targets / Runs (Recon mode)
  createTarget: (name: string, root_domain: string, scope_json?: Record<string, unknown>) =>
    fetchAPI<{ id: string; name: string; root_domain: string; scope_json: any; created_at: string }>(
      `/api/targets`,
      {
        method: "POST",
        body: JSON.stringify({ name, root_domain, scope_json }),
      }
    ),

  listTargets: () =>
    fetchAPI<Array<{ id: string; name: string; root_domain: string; scope_json: any; created_at: string; updated_at?: string }>>(
      `/api/targets`
    ),

  getTarget: (targetId: string) =>
    fetchAPI<{ id: string; name: string; root_domain: string; scope_json: any; created_at: string; updated_at?: string }>(
      `/api/targets/${targetId}`
    ),

  listRuns: (targetId: string) =>
    fetchAPI<
      Array<{
        id: string;
        target_id: string;
        trigger: string;
        status: string;
        started_at: string | null;
        completed_at: string | null;
        created_at: string | null;
      }>
    >(`/api/targets/${targetId}/runs`),

  startPipeline: (targetId: string, max_hosts: number, max_http_targets: number) =>
    fetchAPI<{ status: string; run_id: string; job_id: string }>(`/api/targets/${targetId}/pipeline`, {
      method: "POST",
      body: JSON.stringify({ max_hosts, max_http_targets }),
    }),

  getRun: (runId: string) =>
    fetchAPI<{
      id: string;
      target_id: string;
      trigger: string;
      status: string;
      started_at: string | null;
      completed_at: string | null;
      created_at: string | null;
    }>(`/api/runs/${runId}`),

  discardRun: (runId: string, reason?: string) =>
    fetchAPI<{ status: string; run_id: string }>(`/api/runs/${runId}/discard`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),

  getJob: (jobId: string) =>
    fetchAPI<any>(`/api/jobs/${jobId}`),

  listJobsForRun: (runId: string) =>
    fetchAPI<Array<any>>(`/api/runs/${runId}/jobs`),

  verifyRun: (targetId: string, runId: string) =>
    fetchAPI<{ status: string; verify_jobs_enqueued: number; job_ids: string[] }>(
      `/api/targets/${targetId}/runs/${runId}/verify`,
      { method: "POST" }
    ),

  // Schedules
  listSchedules: (targetId: string) => fetchAPI<Array<any>>(`/api/targets/${targetId}/schedules`),
  createSchedule: (
    targetId: string,
    interval_seconds: number,
    enabled: boolean,
    pipeline_config?: Record<string, unknown>,
    start_immediately?: boolean
  ) =>
    fetchAPI<any>(`/api/targets/${targetId}/schedules`, {
      method: "POST",
      body: JSON.stringify({ interval_seconds, enabled, pipeline_config, start_immediately }),
    }),
  updateSchedule: (scheduleId: string, patch: Record<string, unknown>) =>
    fetchAPI<any>(`/api/schedules/${scheduleId}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),

  // ReconGraph / Inventory
  listAssets: (targetId: string) => fetchAPI<Array<any>>(`/api/targets/${targetId}/assets`),
  listServices: (targetId: string) => fetchAPI<Array<any>>(`/api/targets/${targetId}/services`),
  listEdges: (targetId: string) => fetchAPI<Array<any>>(`/api/targets/${targetId}/edges`),

  // Run diffs (Phase 5)
  getChanges: (targetId: string, runId?: string) =>
    fetchAPI<any>(`/api/targets/${targetId}/changes${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`),

  // Target-level scans/findings (Phase 4)
  listTargetScans: (targetId: string) => fetchAPI<Array<any>>(`/api/targets/${targetId}/scans`),
  listTargetFindings: (targetId: string) => fetchAPI<Array<any>>(`/api/targets/${targetId}/findings`),

  // Sessions
  createSession: (name: string, target: string) =>
    fetchAPI<{ id: string; name: string; target: string }>("/api/sessions", {
      method: "POST",
      body: JSON.stringify({ name, target }),
    }),

  listSessions: () =>
    fetchAPI<Array<{ id: string; name: string; target: string; status: string; created_at: string }>>("/api/sessions"),

  getSession: (id: string) =>
    fetchAPI<{ id: string; name: string; target: string; status: string }>(`/api/sessions/${id}`),

  // Chat
  sendMessage: (sessionId: string, message: string) =>
    fetchAPI<{ status: string }>(`/api/sessions/${sessionId}/chat`, {
      method: "POST",
      body: JSON.stringify({ message }),
    }),

  getMessages: (sessionId: string) =>
    fetchAPI<Array<{ id: string; role: string; content: string; tool_name?: string; created_at: string }>>(
      `/api/sessions/${sessionId}/messages`
    ),

  // Findings
  getFindings: (sessionId: string) =>
    fetchAPI<Array<any>>(`/api/sessions/${sessionId}/findings`),

  updateFinding: (findingId: string, status: string) =>
    fetchAPI<{ id: string; status: string }>(`/api/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  // Scans
  getScans: (sessionId: string) =>
    fetchAPI<Array<any>>(`/api/sessions/${sessionId}/scans`),

  getScan: (scanId: string) =>
    fetchAPI<{
      id: string;
      scanner: string;
      target: string;
      status: string;
      config: any;
      raw_output: string | null;
      started_at: string | null;
      completed_at: string | null;
    }>(`/api/scans/${scanId}`),
};
