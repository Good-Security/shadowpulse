"use client";

import { useState, useCallback, type KeyboardEvent } from "react";
import { api } from "@/lib/api";
import type { Session } from "@/lib/types";

export function TargetInput({
  currentSession,
  onSessionCreated,
  onNewSession,
}: {
  currentSession: Session | null;
  onSessionCreated: (session: Session) => void;
  onNewSession?: () => void;
}) {
  const [target, setTarget] = useState("");
  const [creating, setCreating] = useState(false);

  const handleCreate = useCallback(async () => {
    const trimmed = target.trim();
    if (!trimmed || creating) return;

    setCreating(true);
    try {
      const session = await api.createSession(
        `Pentest - ${trimmed}`,
        trimmed
      );
      onSessionCreated(session as Session);
      setTarget("");
    } catch (err) {
      console.error("Failed to create session:", err);
    } finally {
      setCreating(false);
    }
  }, [target, creating, onSessionCreated]);

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleCreate();
    }
  };

  if (currentSession) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-xs text-sp-muted uppercase tracking-wider">
          Target
        </span>
        <span className="text-sm text-sp-green font-mono glow-green">
          {currentSession.target}
        </span>
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-sp-green/10 text-sp-green border border-sp-green/20 uppercase">
          {currentSession.status}
        </span>
        {onNewSession && (
          <button
            onClick={onNewSession}
            className="text-[10px] uppercase tracking-wider text-sp-muted hover:text-sp-text border border-sp-border px-2 py-0.5 rounded transition-colors"
          >
            New
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-sp-muted uppercase tracking-wider">
        Target
      </span>
      <input
        type="text"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="example.com"
        className="bg-sp-bg border border-sp-border rounded px-2 py-1 text-sm text-sp-text font-mono
          placeholder-sp-muted focus:border-sp-cyan/50 outline-none transition-colors w-48"
      />
      <button
        onClick={handleCreate}
        disabled={!target.trim() || creating}
        className="px-3 py-1 text-xs font-bold uppercase tracking-wider rounded
          bg-sp-cyan/20 text-sp-cyan hover:bg-sp-cyan/30
          disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
      >
        {creating ? "..." : "Lock"}
      </button>
    </div>
  );
}
