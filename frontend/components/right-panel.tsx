"use client";

import { useState } from "react";
import { FindingsBoard } from "./findings-board";
import { RunHistoryPanel } from "./run-history-panel";
import type { WSEvent } from "@/lib/types";

type Tab = "findings" | "history";

export function RightPanel({
  sessionId,
  targetId,
  subscribe,
}: {
  sessionId: string | null;
  targetId: string | null;
  subscribe: (fn: (e: WSEvent) => void) => () => void;
}) {
  const [activeTab, setActiveTab] = useState<Tab>("findings");

  return (
    <div className="flex flex-col h-full">
      {/* Tab bar */}
      <div className="flex border-b border-sp-border bg-sp-surface">
        {([
          { key: "findings" as const, label: "Findings" },
          { key: "history" as const, label: "Run History" },
        ]).map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`flex-1 px-4 py-2 text-[10px] uppercase tracking-wider transition-colors ${
              activeTab === key
                ? "text-sp-cyan border-b-2 border-sp-cyan bg-sp-bg/30"
                : "text-sp-muted hover:text-sp-text"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Panel content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "findings" ? (
          <FindingsBoard sessionId={sessionId} subscribe={subscribe} />
        ) : (
          <RunHistoryPanel targetId={targetId} />
        )}
      </div>
    </div>
  );
}
