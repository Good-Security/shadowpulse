"use client";

import { useState, useEffect } from "react";
import type { WSEvent } from "@/lib/types";

interface ActiveScan {
  id: string;
  scanner: string;
  startedAt: Date;
}

export function ScanProgress({
  subscribe,
}: {
  subscribe: (fn: (e: WSEvent) => void) => () => void;
}) {
  const [activeScans, setActiveScans] = useState<ActiveScan[]>([]);

  useEffect(() => {
    return subscribe((event) => {
      if (event.type === "scan_started") {
        setActiveScans((prev) => [
          ...prev,
          {
            id: event.scan_id,
            scanner: event.scanner,
            startedAt: new Date(),
          },
        ]);
      }
      if (event.type === "scan_completed" || event.type === "scan_failed") {
        setActiveScans((prev) =>
          prev.filter((s) => s.id !== event.scan_id)
        );
      }
    });
  }, [subscribe]);

  if (activeScans.length === 0) return null;

  return (
    <div className="px-4 py-2 border-b border-sp-border bg-sp-surface/30">
      {activeScans.map((scan) => (
        <div key={scan.id} className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-sp-cyan animate-pulse-cyan" />
          <span className="text-xs text-sp-cyan font-mono">
            {scan.scanner}
          </span>
          <div className="flex-1 h-1 bg-sp-border rounded-full overflow-hidden">
            <div className="h-full bg-sp-cyan/50 rounded-full animate-scan-bar" />
          </div>
          <ElapsedTime since={scan.startedAt} />
        </div>
      ))}
    </div>
  );
}

function ElapsedTime({ since }: { since: Date }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setElapsed(Math.floor((Date.now() - since.getTime()) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [since]);

  return (
    <span className="text-[10px] text-sp-muted font-mono">{elapsed}s</span>
  );
}
