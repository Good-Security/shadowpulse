"use client";

import { useState, useEffect, useRef } from "react";
import { SeverityBadge } from "./severity-badge";
import type { ChatMessage, Severity } from "@/lib/types";

const TOOL_LABELS: Record<string, string> = {
  run_subdomain_scan: "subfinder",
  run_port_scan: "nmap",
  run_nuclei_scan: "nuclei",
  run_api_scan: "api_scanner",
  run_owasp_check: "owasp_check",
  run_httpx_probe: "httpx",
  run_tls_scan: "testssl.sh",
  run_directory_fuzz: "ffuf",
  run_crawl: "katana",
  run_dns_scan: "dnsx",
  run_nikto_scan: "nikto",
  generate_report: "report_gen",
};

const TOOL_DESCRIPTIONS: Record<string, string> = {
  run_subdomain_scan: "Subdomain Enumeration",
  run_port_scan: "Port & Service Scan",
  run_nuclei_scan: "Vulnerability Scan",
  run_api_scan: "API Security Test",
  run_owasp_check: "OWASP Configuration Check",
  run_httpx_probe: "HTTP Probe & Tech Detection",
  run_tls_scan: "TLS/SSL Analysis",
  run_directory_fuzz: "Directory Brute-Force",
  run_crawl: "Web Crawling & Discovery",
  run_dns_scan: "DNS Enumeration & Analysis",
  run_nikto_scan: "Web Server Scan",
  generate_report: "Report Generation",
};

export function ChatMessageItem({ message }: { message: ChatMessage }) {
  const isUser = message.role === "user";
  const isTool = message.role === "tool";
  const isFinding = message.role === "finding";

  // Rich tool-call card with raw output (PentAGI style)
  if (isTool) {
    return <ToolCard message={message} />;
  }

  // Inline finding card
  if (isFinding && message.finding) {
    const f = message.finding;
    return (
      <div className="px-4 py-1.5">
        <div className="flex items-center gap-2 px-3 py-2 border border-sp-border rounded-lg bg-sp-surface/50">
          <SeverityBadge severity={f.severity as Severity} />
          <span className="text-xs text-sp-text/80 truncate flex-1">{f.title}</span>
          {f.url && (
            <span className="text-[10px] text-sp-muted font-mono truncate max-w-[150px]">{f.url}</span>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className={`px-4 py-3 ${isUser ? "" : "bg-sp-surface/50"}`}>
      <div className="flex items-start gap-3">
        {/* Avatar */}
        <div
          className={`w-6 h-6 rounded flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5 ${
            isUser
              ? "bg-sp-purple/20 text-sp-purple"
              : "bg-sp-cyan/20 text-sp-cyan"
          }`}
        >
          {isUser ? "U" : "SP"}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span
              className={`text-[10px] font-bold uppercase tracking-wider ${
                isUser ? "text-sp-purple" : "text-sp-cyan"
              }`}
            >
              {isUser ? "You" : "ShadowPulse"}
            </span>
            <span className="text-[10px] text-sp-muted">
              {new Date(message.created_at).toLocaleTimeString()}
            </span>
          </div>
          <div className="text-sm text-sp-text/90 whitespace-pre-wrap break-words leading-relaxed">
            {message.content}
          </div>
        </div>
      </div>
    </div>
  );
}

function ToolCard({ message }: { message: ChatMessage }) {
  const [collapsed, setCollapsed] = useState(false);
  const outputRef = useRef<HTMLDivElement>(null);
  const toolName = message.tool_name || "";
  const label = TOOL_LABELS[toolName] || toolName;
  const desc = TOOL_DESCRIPTIONS[toolName] || toolName;
  const args = message.tool_args;
  const isRunning = message.status === "running";
  const outputLines = message.output_lines || [];
  const [elapsed, setElapsed] = useState(0);

  // Running timer
  useEffect(() => {
    if (!isRunning) return;
    const start = new Date(message.created_at).getTime();
    const interval = setInterval(() => {
      setElapsed(Math.floor((Date.now() - start) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [isRunning, message.created_at]);

  // Auto-scroll output
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [outputLines.length]);

  return (
    <div className="px-4 py-2">
      <div className="border border-sp-yellow/30 rounded-lg bg-sp-bg overflow-hidden">
        {/* Header — tool icon, name, status, collapse toggle */}
        <div
          className="flex items-center justify-between px-3 py-2.5 border-b border-sp-yellow/20 bg-sp-yellow/5 cursor-pointer"
          onClick={() => setCollapsed(!collapsed)}
        >
          <div className="flex items-center gap-2">
            <span className="text-base">&#9881;</span>
            <span className="text-sm font-semibold text-sp-text">{label}</span>
          </div>
          <div className="flex items-center gap-2">
            {isRunning ? (
              <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full border border-sp-yellow/40 text-sp-yellow bg-sp-yellow/10">
                <span className="w-1.5 h-1.5 rounded-full bg-sp-yellow animate-pulse-cyan" />
                Running... ({elapsed}s)
              </span>
            ) : (
              <span className="text-xs px-2 py-0.5 rounded-full border border-sp-green/40 text-sp-green bg-sp-green/10">
                Complete
              </span>
            )}
            <span className="text-sp-muted text-xs">{collapsed ? "+" : "-"}</span>
          </div>
        </div>

        {!collapsed && (
          <>
            {/* Arguments section */}
            {args && Object.keys(args).length > 0 && (
              <div className="px-3 py-2 border-b border-sp-border/50">
                <p className="text-[10px] uppercase text-sp-muted tracking-wider mb-1.5">
                  Arguments
                </p>
                {Object.entries(args).map(([k, v]) => (
                  <div key={k} className="text-xs font-mono">
                    <span className="text-sp-purple">{k}:</span>{" "}
                    <span className="text-sp-text/70">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Raw output terminal */}
            {outputLines.length > 0 && (
              <div className="border-t border-sp-border/50">
                <div className="flex items-center justify-between px-3 py-1.5">
                  <p className="text-[10px] uppercase tracking-wider text-sp-muted">
                    Raw Output{" "}
                    {isRunning && (
                      <span className="text-sp-yellow">(streaming)</span>
                    )}
                  </p>
                  <span className="text-[10px] text-sp-muted">
                    {outputLines.length} lines
                  </span>
                </div>
                <div
                  ref={outputRef}
                  className="max-h-[200px] overflow-y-auto px-3 pb-2 font-mono text-xs leading-relaxed"
                >
                  {outputLines.map((line, i) => (
                    <div key={i} className="text-sp-text/60 hover:text-sp-text/90 transition-colors">
                      {line}
                    </div>
                  ))}
                  {isRunning && (
                    <span className="inline-block w-2 h-3.5 bg-sp-yellow/60 animate-pulse" />
                  )}
                </div>
                {/* Progress bar at bottom */}
                {isRunning && (
                  <div className="h-0.5 bg-sp-border overflow-hidden">
                    <div className="h-full bg-sp-yellow/50 animate-scan-bar" />
                  </div>
                )}
              </div>
            )}

            {/* Empty state when running but no output yet */}
            {outputLines.length === 0 && isRunning && (
              <div className="px-3 py-3 text-xs text-sp-muted font-mono flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-sp-yellow animate-pulse-cyan" />
                Waiting for output...
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export function StreamingMessage({ content }: { content: string }) {
  if (!content) return null;

  return (
    <div className="px-4 py-3 bg-sp-surface/50">
      <div className="flex items-start gap-3">
        <div className="w-6 h-6 rounded flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5 bg-sp-cyan/20 text-sp-cyan">
          SP
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-sp-cyan">
              ShadowPulse
            </span>
            <span className="text-[10px] text-sp-green animate-pulse-cyan">
              thinking...
            </span>
          </div>
          <div className="text-sm text-sp-text/90 whitespace-pre-wrap break-words leading-relaxed">
            {content}
            <span className="inline-block w-2 h-4 bg-sp-cyan/60 animate-pulse ml-0.5" />
          </div>
        </div>
      </div>
    </div>
  );
}
