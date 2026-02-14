"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";

type TargetRow = {
  id: string;
  name: string;
  root_domain: string;
  created_at?: string;
  updated_at?: string;
};

function fmt(ts?: string | null): string {
  if (!ts) return "-";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export default function ReconHome() {
  const [targets, setTargets] = useState<TargetRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [rootDomain, setRootDomain] = useState("");
  const canCreate = useMemo(() => name.trim().length > 0 && rootDomain.trim().length > 0, [name, rootDomain]);

  async function refresh() {
    setLoading(true);
    setErr(null);
    try {
      const rows = await api.listTargets();
      setTargets(rows as any);
    } catch (e: any) {
      setErr(e?.message || "Failed to load targets");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function createTarget() {
    if (!canCreate) return;
    setErr(null);
    try {
      await api.createTarget(name.trim(), rootDomain.trim().toLowerCase());
      setName("");
      setRootDomain("");
      await refresh();
    } catch (e: any) {
      setErr(e?.message || "Failed to create target");
    }
  }

  return (
    <div className="min-h-screen bg-sp-bg text-sp-text">
      <header className="flex items-center justify-between px-4 py-2 border-b border-sp-border bg-sp-surface">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-sp-cyan text-lg glow-cyan">&#9678;</span>
            <span className="text-sm font-bold text-sp-text tracking-widest uppercase">ShadowPulse</span>
          </div>
          <div className="w-px h-5 bg-sp-border" />
          <span className="text-[10px] uppercase tracking-wider text-sp-muted">Recon</span>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/"
            className="text-[10px] uppercase tracking-wider text-sp-muted hover:text-sp-text border border-sp-border px-2 py-1 rounded"
          >
            Command
          </Link>
        </div>
      </header>

      <main className="p-4 max-w-6xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <section className="lg:col-span-1 border border-sp-border bg-sp-surface rounded p-3">
            <div className="text-xs uppercase tracking-wider text-sp-muted mb-2">New Target</div>
            <div className="space-y-2">
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Name (e.g. Pentest - example.com)"
                className="w-full bg-sp-bg border border-sp-border rounded px-2 py-2 text-sm outline-none focus:border-sp-cyan/60"
              />
              <input
                value={rootDomain}
                onChange={(e) => setRootDomain(e.target.value)}
                placeholder="Root domain (e.g. example.com)"
                className="w-full bg-sp-bg border border-sp-border rounded px-2 py-2 text-sm outline-none focus:border-sp-cyan/60"
              />
              <button
                onClick={createTarget}
                disabled={!canCreate}
                className={`w-full px-3 py-2 rounded text-xs uppercase tracking-wider border ${
                  canCreate
                    ? "border-sp-cyan/40 text-sp-cyan hover:bg-sp-cyan/10"
                    : "border-sp-border text-sp-muted opacity-60 cursor-not-allowed"
                }`}
              >
                Create
              </button>

              <button
                onClick={refresh}
                className="w-full px-3 py-2 rounded text-xs uppercase tracking-wider border border-sp-border text-sp-muted hover:text-sp-text"
              >
                {loading ? "Loading..." : "Refresh"}
              </button>
              {err ? <div className="text-xs text-sp-red break-words">{err}</div> : null}
            </div>
          </section>

          <section className="lg:col-span-2 border border-sp-border bg-sp-surface rounded p-3">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs uppercase tracking-wider text-sp-muted">Targets</div>
              <div className="text-[10px] text-sp-muted">{targets.length} total</div>
            </div>

            <div className="overflow-auto">
              <table className="w-full text-sm">
                <thead className="text-[10px] uppercase tracking-wider text-sp-muted">
                  <tr className="border-b border-sp-border">
                    <th className="text-left py-2 pr-2">Name</th>
                    <th className="text-left py-2 pr-2">Root</th>
                    <th className="text-left py-2 pr-2">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.map((t) => (
                    <tr key={t.id} className="border-b border-sp-border/60 hover:bg-sp-bg/40">
                      <td className="py-2 pr-2">
                        <Link href={`/recon/${t.id}`} className="text-sp-cyan hover:underline">
                          {t.name}
                        </Link>
                        <div className="text-[10px] text-sp-muted">{t.id.slice(0, 8)}...</div>
                      </td>
                      <td className="py-2 pr-2 font-mono">{t.root_domain}</td>
                      <td className="py-2 pr-2 text-sp-muted">{fmt(t.created_at || null)}</td>
                    </tr>
                  ))}
                  {targets.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="py-8 text-center text-sm text-sp-muted">
                        No targets yet.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}

