"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import { api } from "@/lib/api";
import type { ChatMessage, WSEvent } from "@/lib/types";

/**
 * Find a tool card by scan_id, falling back to most recent running card.
 */
function findToolIndex(msgs: ChatMessage[], scanId?: string): number {
  if (scanId) {
    for (let i = msgs.length - 1; i >= 0; i--) {
      if (msgs[i].role === "tool" && msgs[i].scan_id === scanId) return i;
    }
  }
  // Fallback: most recent running tool card
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i].role === "tool" && msgs[i].status === "running") return i;
  }
  return -1;
}

export function useChat(sessionId: string | null, subscribe: (fn: (e: WSEvent) => void) => () => void) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [streamingContent, setStreamingContent] = useState("");
  const streamBufferRef = useRef("");

  // Load messages when session changes, hydrating tool cards and findings.
  // Also detect running scans so we can "tap back in" to live output.
  useEffect(() => {
    if (!sessionId) {
      setMessages([]);
      return;
    }

    // Load persisted messages and running scan state in parallel
    Promise.all([
      api.getMessages(sessionId),
      api.getScans(sessionId),
    ]).then(([msgs, scans]) => {
      // Build set of scan_ids that are still running
      const runningScanIds = new Set(
        scans.filter((s: any) => s.status === "running").map((s: any) => s.id)
      );

      setMessages(
        msgs.map((m: any) => {
          const base: ChatMessage = {
            id: m.id,
            role: m.role as ChatMessage["role"],
            content: m.content,
            created_at: m.created_at,
          };

          if (m.role === "tool" && m.tool_name) {
            base.tool_name = m.tool_name;
            base.tool_args = m.tool_args || undefined;
            base.scan_id = m.scan_id || undefined;
            // If this scan is still running, show as live
            if (m.scan_id && runningScanIds.has(m.scan_id)) {
              base.status = "running";
            } else {
              base.status = "complete";
            }
            if (m.tool_output) {
              base.output_lines = m.tool_output.split("\n");
            }
          } else if (m.role === "finding" && m.finding) {
            base.finding = m.finding;
          }

          return base;
        })
      );

      // If any scans are running, we're in a loading state
      if (runningScanIds.size > 0) {
        setIsLoading(true);
      }
    });
  }, [sessionId]);

  // Subscribe to WebSocket events
  useEffect(() => {
    if (!sessionId) return;

    return subscribe((event) => {
      if (event.type === "ai_message") {
        if (event.done) {
          const finalContent = streamBufferRef.current + event.content;
          if (finalContent) {
            setMessages((prev) => [
              ...prev,
              {
                id: `ai-${Date.now()}`,
                role: "assistant",
                content: finalContent,
                created_at: new Date().toISOString(),
              },
            ]);
          }
          streamBufferRef.current = "";
          setStreamingContent("");
          setIsLoading(false);
        } else {
          streamBufferRef.current += event.content;
          setStreamingContent(streamBufferRef.current);
        }
      }

      // Rich tool-call card
      if (event.type === "ai_tool_call") {
        // Flush buffered streaming content
        if (streamBufferRef.current) {
          setMessages((prev) => [
            ...prev,
            {
              id: `ai-${Date.now()}`,
              role: "assistant",
              content: streamBufferRef.current,
              created_at: new Date().toISOString(),
            },
          ]);
          streamBufferRef.current = "";
          setStreamingContent("");
        }

        const toolId = `tool-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
        setMessages((prev) => [
          ...prev,
          {
            id: toolId,
            role: "tool" as const,
            content: "",
            tool_name: event.tool,
            tool_args: event.args,
            scan_id: event.scan_id,
            status: "running",
            created_at: new Date().toISOString(),
          },
        ]);
      }

      // Link scan_id to the most recent tool card when scan starts
      if (event.type === "scan_started") {
        setMessages((prev) => {
          const updated = [...prev];
          // Find the most recent running tool card without a scan_id
          for (let i = updated.length - 1; i >= 0; i--) {
            if (updated[i].role === "tool" && updated[i].status === "running" && !updated[i].scan_id) {
              updated[i] = { ...updated[i], scan_id: event.scan_id };
              break;
            }
          }
          return updated;
        });
      }

      // Append raw output lines — match by scan_id when available
      if (event.type === "tool_output") {
        setMessages((prev) => {
          const updated = [...prev];
          const idx = findToolIndex(updated, event.scan_id);
          if (idx >= 0) {
            const existing = updated[idx].output_lines || [];
            updated[idx] = {
              ...updated[idx],
              output_lines: [...existing, event.line],
            };
          }
          return updated;
        });
      }

      // Mark tool card as complete — match by scan_id
      if (event.type === "scan_completed" || event.type === "scan_failed") {
        setMessages((prev) => {
          const updated = [...prev];
          const idx = findToolIndex(updated, event.scan_id);
          if (idx >= 0) {
            updated[idx] = { ...updated[idx], status: "complete" };
          }
          return updated;
        });
      }

      // Inline finding discovery
      if (event.type === "finding_discovered") {
        setMessages((prev) => [
          ...prev,
          {
            id: `finding-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            role: "finding" as const,
            content: "",
            finding: event.finding,
            created_at: new Date().toISOString(),
          },
        ]);
      }
    });
  }, [sessionId, subscribe]);

  const sendMessage = useCallback(
    async (content: string) => {
      if (!sessionId || !content.trim()) return;

      const userMsg: ChatMessage = {
        id: `user-${Date.now()}`,
        role: "user",
        content,
        created_at: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, userMsg]);
      setIsLoading(true);
      streamBufferRef.current = "";
      setStreamingContent("");

      try {
        await api.sendMessage(sessionId, content);
      } catch {
        setIsLoading(false);
        setMessages((prev) => [
          ...prev,
          {
            id: `error-${Date.now()}`,
            role: "assistant",
            content: "Failed to send message. Check that the backend is running.",
            created_at: new Date().toISOString(),
          },
        ]);
      }
    },
    [sessionId]
  );

  return { messages, sendMessage, isLoading, streamingContent };
}
