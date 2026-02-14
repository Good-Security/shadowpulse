"use client";

import { useEffect, useRef, useCallback, useState } from "react";
import type { WSEvent } from "@/lib/types";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";
const MAX_RECONNECT_ATTEMPTS = 10;
const BASE_RECONNECT_DELAY = 2000;

export function useWebSocket(sessionId: string | null) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const listenersRef = useRef<Set<(event: WSEvent) => void>>(new Set());
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sessionIdRef = useRef(sessionId);

  // Keep sessionId ref in sync for reconnect closure
  useEffect(() => {
    sessionIdRef.current = sessionId;
  }, [sessionId]);

  useEffect(() => {
    if (!sessionId) return;

    reconnectAttemptRef.current = 0;

    function connect() {
      // Don't connect if sessionId changed
      if (sessionIdRef.current !== sessionId) return;

      const ws = new WebSocket(`${WS_URL}/ws/${sessionId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        reconnectAttemptRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as WSEvent;
          listenersRef.current.forEach((fn) => fn(data));
        } catch {
          // Ignore non-JSON messages (like "pong")
        }
      };

      ws.onclose = () => {
        setConnected(false);
        // Auto-reconnect with backoff if session is still active
        if (
          sessionIdRef.current === sessionId &&
          reconnectAttemptRef.current < MAX_RECONNECT_ATTEMPTS
        ) {
          const delay = BASE_RECONNECT_DELAY * Math.pow(1.5, reconnectAttemptRef.current);
          reconnectAttemptRef.current++;
          reconnectTimerRef.current = setTimeout(connect, delay);
        }
      };

      ws.onerror = () => setConnected(false);

      // Ping every 30s to keep alive
      const pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send("ping");
        }
      }, 30000);

      // Store cleanup for this specific connection
      ws.addEventListener("close", () => clearInterval(pingInterval), { once: true });
    }

    connect();

    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [sessionId]);

  const subscribe = useCallback((fn: (event: WSEvent) => void) => {
    listenersRef.current.add(fn);
    return () => {
      listenersRef.current.delete(fn);
    };
  }, []);

  return { connected, subscribe };
}
