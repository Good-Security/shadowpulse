"use client";

import { useState } from "react";

type ChangeItem = {
  id: string;
  type?: string;
  value?: string;
  normalized?: string;
  status: string;
  port?: number;
  proto?: string;
  name?: string | null;
  product?: string | null;
  version?: string | null;
  asset_id?: string;
};

type Changes = {
  target_id: string;
  run_id: string;
  new: { assets: ChangeItem[]; services: ChangeItem[] };
  pending_verification: { assets: ChangeItem[]; services: ChangeItem[] };
  confirmed: {
    closed: { assets: ChangeItem[]; services: ChangeItem[] };
    unresolved: { assets: ChangeItem[]; services: ChangeItem[] };
  };
  counts: Record<string, number>;
};

const TYPE_COLORS: Record<string, string> = {
  subdomain: "text-[#00e5ff] border-[#00e5ff]/40 bg-[#00e5ff]/10",
  host: "text-[#00e5ff] border-[#00e5ff]/40 bg-[#00e5ff]/10",
  ip: "text-[#00ff88] border-[#00ff88]/40 bg-[#00ff88]/10",
  url: "text-[#ffb020] border-[#ffb020]/40 bg-[#ffb020]/10",
};

function ItemRow({ item, isService }: { item: ChangeItem; isService: boolean }) {
  if (isService) {
    return (
      <div className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono border-b border-sp-border/30">
        <span className="text-[10px] uppercase tracking-wider px-1 py-0.5 rounded border text-sp-muted border-sp-border bg-sp-bg/30">
          SVC
        </span>
        <span className="text-sp-cyan">{item.port}</span>
        <span className="text-sp-muted">/{item.proto}</span>
        {item.name && <span className="text-sp-text/70">{item.name}</span>}
        {item.product && (
          <span className="text-sp-muted">
            {item.product}
            {item.version && <span className="text-sp-text/50"> {item.version}</span>}
          </span>
        )}
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 text-xs border-b border-sp-border/30">
      <span className={`text-[10px] uppercase tracking-wider px-1 py-0.5 rounded border ${TYPE_COLORS[item.type || ""] || "text-sp-muted border-sp-border"}`}>
        {item.type}
      </span>
      <span className="font-mono text-sp-text/80 break-all">{item.normalized || item.value}</span>
    </div>
  );
}

function ChangeSection({
  title,
  accentColor,
  assets,
  services,
  defaultOpen,
}: {
  title: string;
  accentColor: string;
  assets: ChangeItem[];
  services: ChangeItem[];
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const total = assets.length + services.length;

  const borderClass =
    accentColor === "green" ? "border-sp-green/30" :
    accentColor === "yellow" ? "border-sp-yellow/30" :
    accentColor === "red" ? "border-sp-red/30" :
    "border-sp-muted/30";

  const bgClass =
    accentColor === "green" ? "bg-sp-green/5" :
    accentColor === "yellow" ? "bg-sp-yellow/5" :
    accentColor === "red" ? "bg-sp-red/5" :
    "bg-sp-muted/5";

  const textClass =
    accentColor === "green" ? "text-sp-green" :
    accentColor === "yellow" ? "text-sp-yellow" :
    accentColor === "red" ? "text-sp-red" :
    "text-sp-muted";

  const countBgClass =
    accentColor === "green" ? "bg-sp-green/10" :
    accentColor === "yellow" ? "bg-sp-yellow/10" :
    accentColor === "red" ? "bg-sp-red/10" :
    "bg-sp-muted/10";

  return (
    <div className={`border rounded-lg overflow-hidden ${borderClass}`}>
      <button
        onClick={() => setOpen(!open)}
        className={`w-full flex items-center justify-between px-3 py-2 ${bgClass} cursor-pointer`}
      >
        <div className="flex items-center gap-2">
          <span className={`text-xs font-semibold ${textClass}`}>{title}</span>
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${countBgClass} ${textClass}`}>
            {total}
          </span>
        </div>
        <span className="text-sp-muted text-xs">{open ? "-" : "+"}</span>
      </button>
      {open && (
        <div>
          {total === 0 ? (
            <div className="px-3 py-3 text-xs text-sp-muted">(none)</div>
          ) : (
            <>
              {assets.map((a) => <ItemRow key={a.id} item={a} isService={false} />)}
              {services.map((s) => <ItemRow key={s.id} item={s} isService={true} />)}
            </>
          )}
        </div>
      )}
    </div>
  );
}

export function ChangeViewer({ changes }: { changes: Changes | null }) {
  if (!changes) {
    return (
      <div className="text-sm text-sp-muted text-center py-8">
        Select a completed run to view changes.
      </div>
    );
  }

  const c = changes.counts;
  const summaryItems = [
    { label: "New Assets", value: c.new_assets, color: "text-sp-green" },
    { label: "New Services", value: c.new_services, color: "text-sp-green" },
    { label: "Pending Verify", value: c.pending_assets + c.pending_services, color: "text-sp-yellow" },
    {
      label: "Closed / Unresolved",
      value: c.confirmed_closed_assets + c.confirmed_closed_services + c.confirmed_unresolved_assets + c.confirmed_unresolved_services,
      color: "text-sp-red",
    },
  ];

  return (
    <div className="space-y-3">
      {/* Summary tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {summaryItems.map((item) => (
          <div key={item.label} className="border border-sp-border rounded p-2 bg-sp-bg/30">
            <div className="text-[10px] uppercase tracking-wider text-sp-muted">{item.label}</div>
            <div className={`text-lg ${item.color}`}>{item.value}</div>
          </div>
        ))}
      </div>

      {/* Expandable sections */}
      <div className="space-y-2">
        <ChangeSection
          title="New Discoveries"
          accentColor="green"
          assets={changes.new.assets}
          services={changes.new.services}
          defaultOpen={true}
        />
        <ChangeSection
          title="Pending Verification"
          accentColor="yellow"
          assets={changes.pending_verification.assets}
          services={changes.pending_verification.services}
          defaultOpen={false}
        />
        <ChangeSection
          title="Confirmed Closed"
          accentColor="red"
          assets={changes.confirmed.closed.assets}
          services={changes.confirmed.closed.services}
          defaultOpen={false}
        />
        <ChangeSection
          title="Unresolved"
          accentColor="gray"
          assets={changes.confirmed.unresolved.assets}
          services={changes.confirmed.unresolved.services}
          defaultOpen={false}
        />
      </div>
    </div>
  );
}
