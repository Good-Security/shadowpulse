"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import { FindingCard } from "./finding-card";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";

const SCANNER_DESCRIPTIONS: Record<string, string> = {
  subfinder: "Subdomain Enumeration",
  nmap: "Port & Service Scan",
  nuclei: "Vulnerability Scan",
  api: "API Security Test",
  owasp: "OWASP Configuration Check",
  httpx: "HTTP Probe & Tech Detection",
  testssl: "TLS/SSL Analysis",
  ffuf: "Directory Brute-Force",
  katana: "Web Crawling & Discovery",
  dnsx: "DNS Enumeration & Analysis",
  nikto: "Web Server Scan",
};

interface Run {
  id: string;
  target_id: string;
  trigger: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string | null;
}

interface ScanSummary {
  id: string;
  scanner: string;
  target: string;
  status: string;
  run_id?: string;
  started_at: string | null;
  completed_at: string | null;
}

function statusBadge(status: string) {
  const colors: Record<string, string> = {
    completed: "text-sp-green bg-sp-green/10",
    running: "text-sp-cyan bg-sp-cyan/10",
    queued: "text-sp-yellow bg-sp-yellow/10",
    failed: "text-sp-red bg-sp-red/10",
    discarded: "text-sp-muted bg-sp-muted/10",
  };
  return (
    <span
      className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-mono ${colors[status] || "text-sp-muted bg-sp-muted/10"}`}
    >
      {status}
    </span>
  );
}

function fmt(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function RunHistoryPanel({ targetId }: { targetId: string | null }) {
  const [runs, setRuns] = useState<Run[]>([]);
  const [allScans, setAllScans] = useState<ScanSummary[]>([]);
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [scanOutputs, setScanOutputs] = useState<Record<string, string>>({});
  const [loadingScanId, setLoadingScanId] = useState<string | null>(null);

  const loadData = useCallback((tid: string) => {
    Promise.all([
      api.listRuns(tid),
      api.listTargetScans(tid),
      api.listTargetFindings(tid),
    ]).then(([r, s, f]) => {
      setRuns(r);
      setAllScans(s);
      setAllFindings(f);
      if (r.length > 0 && !selectedRunId) {
        setSelectedRunId(r[0].id);
      }
    }).catch(() => {});
  }, [selectedRunId]);

  // Fetch data when targetId changes
  useEffect(() => {
    if (!targetId) {
      setRuns([]);
      setAllScans([]);
      setAllFindings([]);
      setSelectedRunId(null);
      return;
    }
    loadData(targetId);
  }, [targetId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll when runs are active
  useEffect(() => {
    if (!targetId) return;
    const hasActive = runs.some((r) => r.status === "running" || r.status === "queued");
    if (!hasActive) return;
    const interval = setInterval(() => loadData(targetId), 5000);
    return () => clearInterval(interval);
  }, [targetId, runs, loadData]);

  const runScans = useMemo(
    () => (selectedRunId ? allScans.filter((s: any) => s.run_id === selectedRunId) : []),
    [allScans, selectedRunId]
  );

  const runFindings = useMemo(
    () => (selectedRunId ? allFindings.filter((f: any) => (f as any).run_id === selectedRunId) : []),
    [allFindings, selectedRunId]
  );

  async function toggleScanOutput(scanId: string) {
    if (expandedScanId === scanId) {
      setExpandedScanId(null);
      return;
    }
    setExpandedScanId(scanId);
    if (!scanOutputs[scanId]) {
      setLoadingScanId(scanId);
      try {
        const detail = await api.getScan(scanId);
        setScanOutputs((prev) => ({ ...prev, [scanId]: detail.raw_output || "(no output)" }));
      } catch {
        setScanOutputs((prev) => ({ ...prev, [scanId]: "(failed to load output)" }));
      } finally {
        setLoadingScanId(null);
      }
    }
  }

  if (!targetId) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-sm text-sp-muted">Create a session to view run history</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Run list */}
      <div className="border-b border-sp-border max-h-[35%] overflow-y-auto">
        <div className="px-4 py-3 border-b border-sp-border">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-sp-cyan uppercase tracking-wider">
              Runs
            </h2>
            <span className="text-xs text-sp-muted">{runs.length} total</span>
          </div>
        </div>
        {runs.length === 0 ? (
          <p className="text-sm text-sp-muted text-center py-6">No runs yet</p>
        ) : (
          <div className="divide-y divide-sp-border/50">
            {runs.map((run) => (
              <button
                key={run.id}
                onClick={() => {
                  setSelectedRunId(run.id);
                  setExpandedScanId(null);
                }}
                className={`w-full text-left px-4 py-2.5 transition-colors ${
                  selectedRunId === run.id
                    ? "bg-sp-cyan/5 border-l-2 border-sp-cyan"
                    : "hover:bg-sp-surface border-l-2 border-transparent"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {statusBadge(run.status)}
                    <span className="text-[10px] text-sp-muted uppercase">{run.trigger}</span>
                  </div>
                  <span className="text-[10px] text-sp-muted font-mono">
                    {run.id.slice(0, 8)}
                  </span>
                </div>
                <div className="text-[10px] text-sp-muted mt-1">
                  {fmt(run.started_at)}
                  {run.completed_at && <> &rarr; {fmt(run.completed_at)}</>}
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Selected run detail */}
      {selectedRunId && (
        <div className="flex-1 overflow-y-auto">
          {/* Scans section */}
          <div className="border-b border-sp-border">
            <div className="px-4 py-2 border-b border-sp-border/50">
              <h3 className="text-[10px] font-bold text-sp-muted uppercase tracking-wider">
                Scans ({runScans.length})
              </h3>
            </div>
            {runScans.length === 0 ? (
              <p className="text-xs text-sp-muted text-center py-4">No scans for this run</p>
            ) : (
              <div className="p-3 space-y-2">
                {runScans.map((scan) => {
                  const isExpanded = expandedScanId === scan.id;
                  const desc = SCANNER_DESCRIPTIONS[scan.scanner] || scan.scanner;
                  const isComplete = scan.status === "completed";
                  const isFailed = scan.status === "failed";
                  const outputLines = scanOutputs[scan.id]
                    ? scanOutputs[scan.id].split("\n").filter((l) => l.trim())
                    : [];
                  const scanFindings = allFindings.filter((f: any) => f.scan_id === scan.id);

                  return (
                    <div
                      key={scan.id}
                      className={`border rounded-lg bg-sp-bg overflow-hidden ${
                        isFailed
                          ? "border-sp-red/30"
                          : isComplete
                            ? "border-sp-green/30"
                            : "border-sp-yellow/30"
                      }`}
                    >
                      {/* Header — matches ToolCard style */}
                      <div
                        className={`flex items-center justify-between px-3 py-2.5 border-b cursor-pointer ${
                          isFailed
                            ? "border-sp-red/20 bg-sp-red/5"
                            : isComplete
                              ? "border-sp-green/20 bg-sp-green/5"
                              : "border-sp-yellow/20 bg-sp-yellow/5"
                        }`}
                        onClick={() => toggleScanOutput(scan.id)}
                      >
                        <div className="flex items-center gap-2">
                          <span className="text-base">&#9881;</span>
                          <span className="text-sm font-semibold text-sp-text">{scan.scanner}</span>
                          <span className="text-[10px] text-sp-muted">{desc}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {isFailed ? (
                            <span className="text-xs px-2 py-0.5 rounded-full border border-sp-red/40 text-sp-red bg-sp-red/10">
                              Failed
                            </span>
                          ) : isComplete ? (
                            <span className="text-xs px-2 py-0.5 rounded-full border border-sp-green/40 text-sp-green bg-sp-green/10">
                              Complete
                            </span>
                          ) : (
                            <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full border border-sp-yellow/40 text-sp-yellow bg-sp-yellow/10">
                              <span className="w-1.5 h-1.5 rounded-full bg-sp-yellow animate-pulse-cyan" />
                              Running
                            </span>
                          )}
                          <span className="text-sp-muted text-xs">{isExpanded ? "-" : "+"}</span>
                        </div>
                      </div>

                      {/* Target info */}
                      <div className="px-3 py-2 border-b border-sp-border/50">
                        <div className="text-xs font-mono">
                          <span className="text-sp-purple">target:</span>{" "}
                          <span className="text-sp-text/70">{scan.target}</span>
                        </div>
                        {scan.started_at && (
                          <div className="text-[10px] text-sp-muted mt-1">
                            {fmt(scan.started_at)}
                            {scan.completed_at && <> &rarr; {fmt(scan.completed_at)}</>}
                          </div>
                        )}
                      </div>

                      {isExpanded && (
                        <>
                          {/* Raw output terminal — matches ToolCard style */}
                          {loadingScanId === scan.id ? (
                            <div className="px-3 py-3 text-xs text-sp-muted font-mono flex items-center gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-sp-yellow animate-pulse-cyan" />
                              Loading output...
                            </div>
                          ) : outputLines.length > 0 ? (
                            <div className="border-t border-sp-border/50">
                              <div className="flex items-center justify-between px-3 py-1.5">
                                <p className="text-[10px] uppercase tracking-wider text-sp-muted">
                                  Raw Output
                                </p>
                                <span className="text-[10px] text-sp-muted">
                                  {outputLines.length} lines
                                </span>
                              </div>
                              <div className="max-h-[300px] overflow-y-auto px-3 pb-2 font-mono text-xs leading-relaxed">
                                {outputLines.map((line, i) => (
                                  <div
                                    key={i}
                                    className="text-sp-text/60 hover:text-sp-text/90 transition-colors"
                                  >
                                    {line}
                                  </div>
                                ))}
                              </div>
                            </div>
                          ) : (
                            <div className="px-3 py-3 text-xs text-sp-muted font-mono">
                              (no output)
                            </div>
                          )}

                          {/* Inline findings for this scan */}
                          {scanFindings.length > 0 && (
                            <div className="border-t border-sp-border/50">
                              <div className="px-3 py-1.5">
                                <p className="text-[10px] uppercase tracking-wider text-sp-muted">
                                  Findings ({scanFindings.length})
                                </p>
                              </div>
                              <div className="px-3 pb-2 space-y-1.5">
                                {scanFindings.map((f) => (
                                  <FindingCard key={f.id} finding={f} />
                                ))}
                              </div>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Findings section */}
          <div>
            <div className="px-4 py-2 border-b border-sp-border/50">
              <h3 className="text-[10px] font-bold text-sp-muted uppercase tracking-wider">
                Findings ({runFindings.length})
              </h3>
            </div>
            {runFindings.length === 0 ? (
              <p className="text-xs text-sp-muted text-center py-4">No findings for this run</p>
            ) : (
              <div className="p-3 space-y-2">
                {runFindings.map((finding) => (
                  <FindingCard key={finding.id} finding={finding} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
