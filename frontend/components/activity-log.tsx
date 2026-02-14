"use client";

import { useState, useEffect, useRef } from "react";
import type { ActivityEvent, WSEvent } from "@/lib/types";

const LEVEL_STYLES: Record<string, string> = {
  info: "text-sp-muted",
  success: "text-sp-green",
  warning: "text-sp-yellow",
  error: "text-sp-red",
};

const LEVEL_DOT: Record<string, string> = {
  info: "bg-sp-muted",
  success: "bg-sp-green",
  warning: "bg-sp-yellow",
  error: "bg-sp-red",
};

export function ActivityLog({
  sessionId,
  subscribe,
}: {
  sessionId: string | null;
  subscribe: (fn: (e: WSEvent) => void) => () => void;
}) {
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!sessionId) {
      setEvents([]);
      return;
    }
    return subscribe((event) => {
      let message = "";
      let level = "info";

      switch (event.type) {
        case "activity":
          message = event.message;
          level = event.level;
          break;
        case "scan_started":
          message = `Scan started: ${event.scanner}`;
          level = "info";
          break;
        case "scan_completed":
          message = `Scan complete: ${event.findings_count} findings`;
          level = "success";
          break;
        case "scan_failed":
          message = `Scan failed: ${event.error}`;
          level = "error";
          break;
        case "finding_discovered":
          message = `[${event.finding.severity.toUpperCase()}] ${event.finding.title}`;
          level =
            event.finding.severity === "critical" || event.finding.severity === "high"
              ? "warning"
              : "info";
          break;
        case "ai_tool_call":
          message = `Tool: ${event.tool}(${JSON.stringify(event.args).slice(0, 60)}...)`;
          level = "info";
          break;
        default:
          return; // Don't log ai_message events
      }

      setEvents((prev) => [
        ...prev,
        {
          id: `${Date.now()}-${Math.random()}`,
          message,
          level,
          timestamp: new Date(),
        },
      ]);
    });
  }, [sessionId, subscribe]);

  // Auto-scroll
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-4 py-3 border-b border-sp-border flex items-center justify-between">
        <h2 className="text-sm font-bold text-sp-cyan uppercase tracking-wider">
          Activity
        </h2>
        <span className="text-xs text-sp-muted">{events.length} events</span>
      </div>

      {/* Event stream */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto">
        {events.length === 0 && (
          <div className="flex items-center justify-center h-full">
            <p className="text-xs text-sp-muted">Waiting for activity...</p>
          </div>
        )}
        {events.map((event) => (
          <div
            key={event.id}
            className="flex items-start gap-2 px-3 py-1.5 hover:bg-sp-surface/30 transition-colors"
          >
            <div
              className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${
                LEVEL_DOT[event.level] || LEVEL_DOT.info
              }`}
            />
            <div className="flex-1 min-w-0">
              <span className="text-[10px] text-sp-muted mr-2">
                {event.timestamp.toLocaleTimeString()}
              </span>
              <span
                className={`text-xs font-mono ${
                  LEVEL_STYLES[event.level] || LEVEL_STYLES.info
                }`}
              >
                {event.message}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
