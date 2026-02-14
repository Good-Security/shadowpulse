"use client";

import { SEVERITY_COLORS, type Severity } from "@/lib/types";

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
  info: "INFO",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border rounded ${SEVERITY_COLORS[severity]}`}
    >
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

export function SeverityCounts({
  counts,
  activeFilter,
  onFilter,
}: {
  counts: Record<Severity, number>;
  activeFilter?: Severity | "all";
  onFilter?: (severity: Severity | "all") => void;
}) {
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  return (
    <div className="flex items-center gap-2">
      {severities.map((s) => {
        const isActive = activeFilter === s;
        const isClickable = !!onFilter;
        return (
          <button
            key={s}
            onClick={() => {
              if (!onFilter) return;
              onFilter(isActive ? "all" : s);
            }}
            className={`flex items-center gap-1 transition-opacity ${
              isClickable ? "cursor-pointer hover:opacity-80" : "cursor-default"
            } ${
              activeFilter && activeFilter !== "all" && !isActive
                ? "opacity-40"
                : "opacity-100"
            }`}
          >
            <SeverityBadge severity={s} />
            <span className="text-xs text-sp-muted">{counts[s] || 0}</span>
          </button>
        );
      })}
    </div>
  );
}
