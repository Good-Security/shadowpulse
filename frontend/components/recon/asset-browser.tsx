"use client";

import { useState, useMemo } from "react";

type Asset = {
  id: string;
  type: string;
  value: string;
  normalized: string;
  status: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  verified_at: string | null;
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

const ASSET_TYPES = ["subdomain", "host", "ip", "url"] as const;
const STATUSES = ["active", "stale", "closed", "unresolved"] as const;

const TYPE_COLORS: Record<string, string> = {
  subdomain: "text-[#00e5ff] border-[#00e5ff]/40 bg-[#00e5ff]/10",
  host: "text-[#00e5ff] border-[#00e5ff]/40 bg-[#00e5ff]/10",
  ip: "text-[#00ff88] border-[#00ff88]/40 bg-[#00ff88]/10",
  url: "text-[#ffb020] border-[#ffb020]/40 bg-[#ffb020]/10",
};

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

export function AssetBrowser({ assets, services }: { assets: Asset[]; services: Service[] }) {
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const typeCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of assets) c[a.type] = (c[a.type] || 0) + 1;
    return c;
  }, [assets]);

  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of assets) c[a.status] = (c[a.status] || 0) + 1;
    return c;
  }, [assets]);

  const servicesByAsset = useMemo(() => {
    const m: Record<string, Service[]> = {};
    for (const s of services) {
      if (!m[s.asset_id]) m[s.asset_id] = [];
      m[s.asset_id].push(s);
    }
    // Sort services by port within each asset
    for (const k of Object.keys(m)) m[k].sort((a, b) => a.port - b.port);
    return m;
  }, [services]);

  const filtered = useMemo(() => {
    let list = assets;
    if (typeFilter !== "all") list = list.filter((a) => a.type === typeFilter);
    if (statusFilter !== "all") list = list.filter((a) => a.status === statusFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((a) => a.normalized.toLowerCase().includes(q) || a.value.toLowerCase().includes(q));
    }
    return list;
  }, [assets, typeFilter, statusFilter, search]);

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Type filter */}
        <div className="flex items-center gap-1">
          <span className="text-[10px] uppercase tracking-wider text-sp-muted mr-1">Type</span>
          <button
            onClick={() => setTypeFilter("all")}
            className={`px-2 py-0.5 text-[10px] uppercase rounded border transition-opacity ${
              typeFilter === "all"
                ? "border-sp-cyan/40 text-sp-cyan bg-sp-cyan/10"
                : "border-sp-border text-sp-muted hover:text-sp-text opacity-50"
            }`}
          >
            All ({assets.length})
          </button>
          {ASSET_TYPES.map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(typeFilter === t ? "all" : t)}
              className={`px-2 py-0.5 text-[10px] uppercase rounded border transition-opacity ${
                typeFilter === t
                  ? TYPE_COLORS[t]
                  : `border-sp-border text-sp-muted hover:text-sp-text ${typeFilter !== "all" ? "opacity-40" : "opacity-70"}`
              }`}
            >
              {t} ({typeCounts[t] || 0})
            </button>
          ))}
        </div>

        {/* Status filter */}
        <div className="flex items-center gap-1">
          <span className="text-[10px] uppercase tracking-wider text-sp-muted mr-1">Status</span>
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

        {/* Search */}
        <input
          type="text"
          placeholder="Search assets..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="bg-sp-bg border border-sp-border rounded px-2 py-1 text-xs outline-none focus:border-sp-cyan/60 w-48"
        />
      </div>

      {/* Results count */}
      <div className="text-[10px] text-sp-muted">
        {filtered.length} of {assets.length} assets
      </div>

      {/* Table */}
      <div className="overflow-auto max-h-[65vh] border border-sp-border rounded bg-sp-bg/30">
        <table className="w-full text-sm">
          <thead className="text-[10px] uppercase tracking-wider text-sp-muted sticky top-0 bg-sp-surface">
            <tr className="border-b border-sp-border">
              <th className="text-left py-2 px-3 w-8"></th>
              <th className="text-left py-2 px-2">Type</th>
              <th className="text-left py-2 px-2">Value</th>
              <th className="text-left py-2 px-2">Status</th>
              <th className="text-left py-2 px-2">First Seen</th>
              <th className="text-left py-2 px-2">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => {
              const assetServices = servicesByAsset[a.id] || [];
              const isExpanded = expandedId === a.id;
              return (
                <AssetRow
                  key={a.id}
                  asset={a}
                  services={assetServices}
                  isExpanded={isExpanded}
                  onToggle={() => setExpandedId(isExpanded ? null : a.id)}
                />
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-sm text-sp-muted">
                  No assets match filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AssetRow({
  asset,
  services,
  isExpanded,
  onToggle,
}: {
  asset: Asset;
  services: Service[];
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const hasServices = services.length > 0;

  return (
    <>
      <tr
        className={`border-b border-sp-border/60 ${hasServices ? "cursor-pointer hover:bg-sp-surface/50" : ""} ${isExpanded ? "bg-sp-surface/30" : ""}`}
        onClick={hasServices ? onToggle : undefined}
      >
        <td className="py-2 px-3 text-sp-muted text-xs">
          {hasServices ? (
            <span className="text-sp-muted">{isExpanded ? "\u25BE" : "\u25B8"}</span>
          ) : null}
        </td>
        <td className="py-2 px-2">
          <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${TYPE_COLORS[asset.type] || "text-sp-muted border-sp-border"}`}>
            {asset.type}
          </span>
        </td>
        <td className="py-2 px-2 font-mono text-xs break-all">{asset.normalized}</td>
        <td className="py-2 px-2">
          <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${STATUS_COLORS[asset.status] || "text-sp-muted border-sp-border"}`}>
            {asset.status}
          </span>
        </td>
        <td className="py-2 px-2 text-[10px] text-sp-muted whitespace-nowrap">{fmt(asset.first_seen_at)}</td>
        <td className="py-2 px-2 text-[10px] text-sp-muted whitespace-nowrap">{fmt(asset.last_seen_at)}</td>
      </tr>
      {isExpanded && services.map((s) => (
        <tr key={s.id} className="border-b border-sp-border/30 bg-sp-bg/50">
          <td className="py-1.5 px-3"></td>
          <td className="py-1.5 px-2">
            <span className="text-[10px] text-sp-muted">SVC</span>
          </td>
          <td className="py-1.5 px-2 font-mono text-xs">
            <span className="text-sp-cyan">{s.port}</span>
            <span className="text-sp-muted">/{s.proto}</span>
            {s.name && <span className="text-sp-text/70 ml-2">{s.name}</span>}
            {s.product && (
              <span className="text-sp-muted ml-2">
                {s.product}
                {s.version && <span className="text-sp-text/50"> {s.version}</span>}
              </span>
            )}
          </td>
          <td className="py-1.5 px-2">
            <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${STATUS_COLORS[s.status] || "text-sp-muted border-sp-border"}`}>
              {s.status}
            </span>
          </td>
          <td className="py-1.5 px-2 text-[10px] text-sp-muted whitespace-nowrap">{fmt(s.first_seen_at)}</td>
          <td className="py-1.5 px-2 text-[10px] text-sp-muted whitespace-nowrap">{fmt(s.last_seen_at)}</td>
        </tr>
      ))}
    </>
  );
}
