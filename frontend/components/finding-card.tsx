"use client";

import { useState } from "react";
import { SeverityBadge } from "./severity-badge";
import type { Finding } from "@/lib/types";

export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="border border-sp-border rounded-lg hover:border-sp-cyan/30 transition-colors cursor-pointer bg-sp-surface overflow-hidden"
      onClick={() => setExpanded(!expanded)}
    >
      {/* Header — always visible */}
      <div className="p-3">
        <div className="flex items-start gap-2">
          <SeverityBadge severity={finding.severity} />
          <div className="flex-1 min-w-0">
            <h4 className="text-sm font-medium text-sp-text truncate">
              {finding.title}
            </h4>
            {finding.url && (
              <p className="text-xs text-sp-muted mt-0.5 truncate font-mono">
                {finding.url}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {finding.cve && (
              <span className="text-[10px] text-sp-purple font-mono">
                {finding.cve}
              </span>
            )}
            <span className="text-sp-muted text-xs">{expanded ? "\u2212" : "+"}</span>
          </div>
        </div>

        {/* Description — always shown (truncated when collapsed) */}
        {finding.description && (
          <p className={`text-xs text-sp-text/70 mt-2 leading-relaxed ${expanded ? "" : "line-clamp-2"}`}>
            {finding.description}
          </p>
        )}
      </div>

      {/* Expanded detail sections */}
      {expanded && (
        <div className="border-t border-sp-border">
          {/* Impact — why this matters */}
          {finding.impact && (
            <div className="px-3 py-2.5 border-b border-sp-border/50 bg-sp-red/5">
              <p className="text-[10px] uppercase text-sp-red/80 tracking-wider font-bold mb-1.5 flex items-center gap-1.5">
                <span>&#9888;</span> Why This Is Dangerous
              </p>
              <p className="text-xs text-sp-text/80 leading-relaxed">
                {finding.impact}
              </p>
            </div>
          )}

          {/* Evidence */}
          {finding.evidence && (
            <div className="px-3 py-2.5 border-b border-sp-border/50">
              <p className="text-[10px] uppercase text-sp-muted tracking-wider mb-1.5">
                Evidence
              </p>
              <pre className="text-xs text-sp-green/80 bg-sp-bg p-2 rounded overflow-x-auto whitespace-pre-wrap">
                {finding.evidence}
              </pre>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div className="px-3 py-2.5 border-b border-sp-border/50 bg-sp-cyan/5">
              <p className="text-[10px] uppercase text-sp-cyan/80 tracking-wider font-bold mb-1.5 flex items-center gap-1.5">
                <span>&#10004;</span> How To Fix
              </p>
              <p className="text-xs text-sp-text/80 leading-relaxed">
                {finding.remediation}
              </p>
            </div>
          )}

          {/* Remediation code example */}
          {finding.remediation_example && (
            <div className="px-3 py-2.5 border-b border-sp-border/50">
              <p className="text-[10px] uppercase text-sp-muted tracking-wider mb-1.5">
                Fix Example
              </p>
              <pre className="text-xs text-sp-cyan/80 bg-sp-bg p-2.5 rounded overflow-x-auto whitespace-pre-wrap font-mono leading-relaxed">
                {finding.remediation_example}
              </pre>
            </div>
          )}

          {/* Footer metadata */}
          <div className="px-3 py-2 flex items-center gap-3 text-[10px] text-sp-muted">
            {finding.cvss_score > 0 && (
              <span>CVSS: <span className="text-sp-text/70 font-mono">{finding.cvss_score.toFixed(1)}</span></span>
            )}
            {finding.cve && (
              <span>{finding.cve}</span>
            )}
            {finding.status && (
              <span className="capitalize">{finding.status}</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
