"use client";

import { useState, useEffect } from "react";
import { FindingCard } from "./finding-card";
import { SeverityCounts } from "./severity-badge";
import { api } from "@/lib/api";
import type { Finding, Severity, WSEvent } from "@/lib/types";

export function FindingsBoard({
  sessionId,
  subscribe,
}: {
  sessionId: string | null;
  subscribe: (fn: (e: WSEvent) => void) => () => void;
}) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filter, setFilter] = useState<Severity | "all">("all");

  // Load findings when session changes
  useEffect(() => {
    if (!sessionId) {
      setFindings([]);
      return;
    }
    api.getFindings(sessionId).then(setFindings).catch(() => {});
  }, [sessionId]);

  // Subscribe to new findings via WebSocket
  useEffect(() => {
    if (!sessionId) return;
    return subscribe((event) => {
      if (event.type === "finding_discovered") {
        setFindings((prev) => [event.finding, ...prev]);
      }
    });
  }, [sessionId, subscribe]);

  const counts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<
      Severity,
      number
    >
  );

  const filtered =
    filter === "all" ? findings : findings.filter((f) => f.severity === filter);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-4 py-3 border-b border-sp-border">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-sm font-bold text-sp-cyan uppercase tracking-wider">
            Findings
          </h2>
          <span className="text-xs text-sp-muted">{findings.length} total</span>
        </div>
        <SeverityCounts counts={counts} activeFilter={filter} onFilter={setFilter} />
      </div>

      {/* Findings list */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {!sessionId && (
          <p className="text-sm text-sp-muted text-center mt-8">
            Create a session to start
          </p>
        )}
        {sessionId && filtered.length === 0 && (
          <p className="text-sm text-sp-muted text-center mt-8">
            No findings yet. Start a scan from the chat.
          </p>
        )}
        {filtered.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </div>
    </div>
  );
}
