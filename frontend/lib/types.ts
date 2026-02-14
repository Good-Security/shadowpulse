export interface Session {
  id: string;
  name: string;
  target: string;
  target_id?: string;
  status: string;
  created_at: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system" | "tool" | "finding";
  content: string;
  tool_name?: string;
  tool_args?: Record<string, unknown>;
  tool_output?: string;
  scan_id?: string;
  finding_id?: string;
  status?: "running" | "complete";
  finding?: Finding;
  output_lines?: string[];
  created_at: string;
}

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  impact: string;
  url: string;
  cve: string;
  cvss_score: number;
  status: string;
  remediation: string;
  remediation_example: string;
  evidence: string;
  scan_id: string;
  created_at: string;
}

export interface ScanInfo {
  id: string;
  scanner: string;
  target: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

// WebSocket event types
export type WSEvent =
  | { type: "scan_started"; scan_id: string; scanner: string }
  | { type: "scan_completed"; scan_id: string; findings_count: number }
  | { type: "scan_failed"; scan_id: string; error: string }
  | { type: "finding_discovered"; finding: Finding }
  | { type: "ai_message"; content: string; done: boolean }
  | { type: "ai_tool_call"; tool: string; args: Record<string, unknown>; scan_id?: string }
  | { type: "tool_output"; line: string; scan_id?: string }
  | { type: "activity"; message: string; level: string };

export interface ActivityEvent {
  id: string;
  message: string;
  level: string;
  timestamp: Date;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "text-sp-red bg-sp-red/10 border-sp-red/30",
  high: "text-sp-orange bg-sp-orange/10 border-sp-orange/30",
  medium: "text-sp-yellow bg-sp-yellow/10 border-sp-yellow/30",
  low: "text-sp-cyan bg-sp-cyan/10 border-sp-cyan/30",
  info: "text-sp-muted bg-sp-muted/10 border-sp-muted/30",
};
