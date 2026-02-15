"use client";

import { useState, useMemo } from "react";

type Asset = {
  id: string;
  type: string;
  value: string;
  normalized: string;
  status: string;
};

type Service = {
  id: string;
  asset_id: string;
  port: number;
  proto: string;
  name: string | null;
  product: string | null;
  version: string | null;
  status: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
};

const STATUSES = ["active", "stale", "closed"] as const;

const STATUS_COLORS: Record<string, string> = {
  active: "text-sp-green border-sp-green/40 bg-sp-green/10",
  stale: "text-sp-yellow border-sp-yellow/40 bg-sp-yellow/10",
  closed: "text-sp-red border-sp-red/40 bg-sp-red/10",
  unresolved: "text-sp-muted border-sp-muted/40 bg-sp-muted/10",
};

function fmt(ts?: string | null): string {
  if (!ts) return "-";
  try {
    const d = new Date(ts);
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch {
    return ts;
  }
}

export function ServiceBrowser({ services, assets }: { services: Service[]; assets: Asset[] }) {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const assetMap = useMemo(() => {
    const m: Record<string, Asset> = {};
    for (const a of assets) m[a.id] = a;
    return m;
  }, [assets]);

  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of services) c[s.status] = (c[s.status] || 0) + 1;
    return c;
  }, [services]);

  const filtered = useMemo(() => {
    let list = [...services].sort((a, b) => a.port - b.port);
    if (statusFilter !== "all") list = list.filter((s) => s.status === statusFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((s) => {
        const asset = assetMap[s.asset_id];
        return (
          String(s.port).includes(q) ||
          (s.name && s.name.toLowerCase().includes(q)) ||
          (s.product && s.product.toLowerCase().includes(q)) ||
          (s.version && s.version.toLowerCase().includes(q)) ||
          (asset && asset.normalized.toLowerCase().includes(q))
        );
      });
    }
    return list;
  }, [services, statusFilter, search, assetMap]);

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1">
          <span className="text-[10px] uppercase tracking-wider text-sp-muted mr-1">Status</span>
          <button
            onClick={() => setStatusFilter("all")}
            className={`px-2 py-0.5 text-[10px] uppercase rounded border transition-opacity ${
              statusFilter === "all"
                ? "border-sp-cyan/40 text-sp-cyan bg-sp-cyan/10"
                : "border-sp-border text-sp-muted hover:text-sp-text opacity-50"
            }`}
          >
            All ({services.length})
          </button>
          {STATUSES.map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(statusFilter === s ? "all" : s)}
              className={`px-2 py-0.5 text-[10px] uppercase rounded border transition-opacity ${
                statusFilter === s
                  ? STATUS_COLORS[s]
                  : `border-sp-border text-sp-muted hover:text-sp-text ${statusFilter !== "all" ? "opacity-40" : "opacity-70"}`
              }`}
            >
              {s} ({statusCounts[s] || 0})
            </button>
          ))}
        </div>

        <input
          type="text"
          placeholder="Search port, name, product..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="bg-sp-bg border border-sp-border rounded px-2 py-1 text-xs outline-none focus:border-sp-cyan/60 w-56"
        />
      </div>

      <div className="text-[10px] text-sp-muted">
        {filtered.length} of {services.length} services
      </div>

      {/* Table */}
      <div className="overflow-auto max-h-[65vh] border border-sp-border rounded bg-sp-bg/30">
        <table className="w-full text-sm">
          <thead className="text-[10px] uppercase tracking-wider text-sp-muted sticky top-0 bg-sp-surface">
            <tr className="border-b border-sp-border">
              <th className="text-left py-2 px-2">Asset</th>
              <th className="text-left py-2 px-2">Port</th>
              <th className="text-left py-2 px-2">Proto</th>
              <th className="text-left py-2 px-2">Name</th>
              <th className="text-left py-2 px-2">Product</th>
              <th className="text-left py-2 px-2">Version</th>
              <th className="text-left py-2 px-2">Status</th>
              <th className="text-left py-2 px-2">First Seen</th>
              <th className="text-left py-2 px-2">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => {
              const asset = assetMap[s.asset_id];
              return (
                <tr key={s.id} className="border-b border-sp-border/60 hover:bg-sp-surface/30">
                  <td className="py-2 px-2 font-mono text-xs text-sp-text/70 max-w-[200px] truncate">
                    {asset?.normalized || s.asset_id.slice(0, 8)}
                  </td>
                  <td className="py-2 px-2 font-mono text-sp-cyan">{s.port}</td>
                  <td className="py-2 px-2 font-mono text-sp-muted">{s.proto}</td>
                  <td className="py-2 px-2 text-sp-text/70">{s.name || "-"}</td>
                  <td className="py-2 px-2 text-sp-text/70">{s.product || "-"}</td>
                  <td className="py-2 px-2 text-sp-muted">{s.version || "-"}</td>
                  <td className="py-2 px-2">
                    <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${STATUS_COLORS[s.status] || "text-sp-muted border-sp-border"}`}>
                      {s.status}
                    </span>
                  </td>
                  <td className="py-2 px-2 text-[10px] text-sp-muted whitespace-nowrap">{fmt(s.first_seen_at)}</td>
                  <td className="py-2 px-2 text-[10px] text-sp-muted whitespace-nowrap">{fmt(s.last_seen_at)}</td>
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={9} className="py-8 text-center text-sm text-sp-muted">
                  No services match filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
