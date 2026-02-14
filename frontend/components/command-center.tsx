"use client";

import { useState, useCallback, useEffect } from "react";
import Link from "next/link";
import { useWebSocket } from "@/hooks/use-websocket";
import { useChat } from "@/hooks/use-chat";
import { ChatPanel } from "./chat-panel";
import { RightPanel } from "./right-panel";
import { ScanProgress } from "./scan-progress";
import { TargetInput } from "./target-input";
import { api } from "@/lib/api";
import type { Session } from "@/lib/types";

const SESSION_STORAGE_KEY = "sp_session_id";

export function CommandCenter() {
  const [session, setSession] = useState<Session | null>(null);
  const { connected, subscribe } = useWebSocket(session?.id ?? null);
  const { messages, sendMessage, isLoading, streamingContent } = useChat(
    session?.id ?? null,
    subscribe
  );

  // Restore session from localStorage on mount
  useEffect(() => {
    const storedId = localStorage.getItem(SESSION_STORAGE_KEY);
    if (storedId && !session) {
      api
        .getSession(storedId)
        .then((restored) => {
          setSession(restored as Session);
        })
        .catch(() => {
          localStorage.removeItem(SESSION_STORAGE_KEY);
        });
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSessionCreated = useCallback((newSession: Session) => {
    setSession(newSession);
    localStorage.setItem(SESSION_STORAGE_KEY, newSession.id);
  }, []);

  const handleNewSession = useCallback(() => {
    setSession(null);
    localStorage.removeItem(SESSION_STORAGE_KEY);
  }, []);

  return (
    <div className="flex flex-col h-screen">
      {/* Top bar */}
      <header className="flex items-center justify-between px-4 py-2 border-b border-sp-border bg-sp-surface">
        <div className="flex items-center gap-3">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <span className="text-sp-cyan text-lg glow-cyan">&#9678;</span>
            <span className="text-sm font-bold text-sp-text tracking-widest uppercase">
              ShadowPulse
            </span>
          </div>
          <div className="w-px h-5 bg-sp-border" />
          <TargetInput
            currentSession={session}
            onSessionCreated={handleSessionCreated}
            onNewSession={handleNewSession}
          />
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/recon"
            className="text-[10px] uppercase tracking-wider text-sp-muted hover:text-sp-text border border-sp-border px-2 py-1 rounded"
          >
            Recon
          </Link>
          {/* Connection status */}
          <div className="flex items-center gap-1.5">
            <div
              className={`w-2 h-2 rounded-full ${
                connected
                  ? "bg-sp-green shadow-[0_0_6px_rgba(0,255,136,0.5)]"
                  : "bg-sp-red"
              }`}
            />
            <span className="text-[10px] text-sp-muted uppercase tracking-wider">
              {connected ? "Live" : "Offline"}
            </span>
          </div>
        </div>
      </header>

      {/* Scan progress bar */}
      <ScanProgress subscribe={subscribe} />

      {/* Main 2-pane layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Chat Panel — 60% (rich stream with tool cards + inline findings) */}
        <div className="w-[60%] border-r border-sp-border flex flex-col">
          <ChatPanel
            messages={messages}
            streamingContent={streamingContent}
            isLoading={isLoading}
            onSend={sendMessage}
          />
        </div>

        {/* Right Panel — 40% (Findings + Run History tabs) */}
        <div className="w-[40%] flex flex-col">
          <RightPanel
            sessionId={session?.id ?? null}
            targetId={session?.target_id ?? null}
            subscribe={subscribe}
          />
        </div>
      </div>

      {/* Bottom status bar */}
      <footer className="flex items-center justify-between px-4 py-1.5 border-t border-sp-border bg-sp-surface text-[10px] text-sp-muted">
        <div className="flex items-center gap-4">
          <span>
            {session
              ? `Session: ${session.id.slice(0, 8)}...`
              : "No active session"}
          </span>
        </div>
        <div className="flex items-center gap-4">
          <span>SHADOWPULSE v0.1.0</span>
          <span>AI-Native Security Platform</span>
        </div>
      </footer>
    </div>
  );
}
