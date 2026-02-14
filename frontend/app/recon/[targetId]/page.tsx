"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { ReconGraph } from "@/components/recon/recon-graph";

type RunRow = {
  id: string;
  target_id: string;
  trigger: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string | null;
};

function fmt(ts?: string | null): string {
  if (!ts) return "-";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function badge(status: string): string {
  const s = (status || "").toLowerCase();
  if (s === "completed") return "border-sp-green/40 text-sp-green bg-sp-green/10";
  if (s === "running") return "border-sp-cyan/40 text-sp-cyan bg-sp-cyan/10";
  if (s === "queued") return "border-sp-yellow/40 text-sp-yellow bg-sp-yellow/10";
  if (s === "failed") return "border-sp-red/40 text-sp-red bg-sp-red/10";
  if (s === "discarded" || s === "cancelled") return "border-sp-muted/40 text-sp-muted bg-sp-muted/10";
  return "border-sp-border text-sp-muted bg-sp-bg/30";
}

export default function TargetReconPage({ params }: { params: { targetId: string } }) {
  const targetId = params.targetId;
  const [target, setTarget] = useState<any>(null);
  const [runs, setRuns] = useState<RunRow[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);

  const [schedules, setSchedules] = useState<any[]>([]);
  const [jobs, setJobs] = useState<any[]>([]);
  const [changes, setChanges] = useState<any>(null);

  const [assets, setAssets] = useState<any[]>([]);
  const [services, setServices] = useState<any[]>([]);
  const [edges, setEdges] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);

  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const [maxHosts, setMaxHosts] = useState(10);
  const [maxHttpTargets, setMaxHttpTargets] = useState(50);

  const [scheduleInterval, setScheduleInterval] = useState(3600);
  const [scheduleEnabled, setScheduleEnabled] = useState(true);

  const selectedRun = useMemo(() => runs.find((r) => r.id === selectedRunId) || null, [runs, selectedRunId]);
  const hasActiveRun = useMemo(
    () => runs.some((r) => ["queued", "running"].includes((r.status || "").toLowerCase())),
    [runs]
  );

  async function loadAll() {
    setErr(null);
    try {
      const [t, r, sch, a, s, e, sc, f] = await Promise.all([
        api.getTarget(targetId),
        api.listRuns(targetId),
        api.listSchedules(targetId),
        api.listAssets(targetId),
        api.listServices(targetId),
        api.listEdges(targetId),
        api.listTargetScans(targetId),
        api.listTargetFindings(targetId),
      ]);
      setTarget(t);
      setRuns(r as any);
      setSchedules(sch as any);
      setAssets(a as any);
      setServices(s as any);
      setEdges(e as any);
      setScans(sc as any);
      setFindings(f as any);
      setSelectedRunId((prev) => prev || (r as any)?.[0]?.id || null);
    } catch (e: any) {
      setErr(e?.message || "Failed to load target");
    }
  }

  async function loadRunExtras(runId: string) {
    setErr(null);
    try {
      const [c, j] = await Promise.all([api.getChanges(targetId, runId), api.listJobsForRun(runId)]);
      setChanges(c);
      setJobs(j as any);
    } catch (e: any) {
      setErr(e?.message || "Failed to load run details");
    }
  }

  useEffect(() => {
    loadAll();
  }, [targetId]);

  useEffect(() => {
    if (!selectedRunId) return;
    loadRunExtras(selectedRunId);
  }, [selectedRunId]);

  useEffect(() => {
    if (!hasActiveRun) return;
    const t = setInterval(() => {
      api.listRuns(targetId).then((r) => setRuns(r as any)).catch(() => {});
      if (selectedRunId) {
        loadRunExtras(selectedRunId);
      }
    }, 5000);
    return () => clearInterval(t);
  }, [hasActiveRun, targetId, selectedRunId]);

  async function startRun() {
    setBusy("start");
    setErr(null);
    try {
      const res = await api.startPipeline(targetId, maxHosts, maxHttpTargets);
      const r = await api.listRuns(targetId);
      setRuns(r as any);
      setSelectedRunId(res.run_id);
      await loadRunExtras(res.run_id);
    } catch (e: any) {
      setErr(e?.message || "Failed to start pipeline");
    } finally {
      setBusy(null);
    }
  }

  async function discardSelected() {
    if (!selectedRunId) return;
    setBusy("discard");
    setErr(null);
    try {
      await api.discardRun(selectedRunId, "discarded_from_ui");
      const r = await api.listRuns(targetId);
      setRuns(r as any);
      await loadRunExtras(selectedRunId);
    } catch (e: any) {
      setErr(e?.message || "Failed to discard run");
    } finally {
      setBusy(null);
    }
  }

  async function verifySelected() {
    if (!selectedRunId) return;
    setBusy("verify");
    setErr(null);
    try {
      await api.verifyRun(targetId, selectedRunId);
      await loadRunExtras(selectedRunId);
    } catch (e: any) {
      setErr(e?.message || "Failed to enqueue verification");
    } finally {
      setBusy(null);
    }
  }

  async function createSchedule() {
    setBusy("schedule");
    setErr(null);
    try {
      await api.createSchedule(
        targetId,
        scheduleInterval,
        scheduleEnabled,
        { max_hosts: maxHosts, max_http_targets: maxHttpTargets },
        false
      );
      const sch = await api.listSchedules(targetId);
      setSchedules(sch as any);
    } catch (e: any) {
      setErr(e?.message || "Failed to create schedule");
    } finally {
      setBusy(null);
    }
  }

  const runScans = useMemo(() => (selectedRunId ? scans.filter((s) => s.run_id === selectedRunId) : []), [scans, selectedRunId]);
  const runFindings = useMemo(() => (selectedRunId ? findings.filter((f) => f.run_id === selectedRunId) : []), [findings, selectedRunId]);

  return (
    <div className="min-h-screen bg-sp-bg text-sp-text">
      <header className="flex items-center justify-between px-4 py-2 border-b border-sp-border bg-sp-surface">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-sp-cyan text-lg glow-cyan">&#9678;</span>
            <span className="text-sm font-bold text-sp-text tracking-widest uppercase">ShadowPulse</span>
          </div>
          <div className="w-px h-5 bg-sp-border" />
          <Link href="/recon" className="text-[10px] uppercase tracking-wider text-sp-muted hover:text-sp-text">
            Recon
          </Link>
          <span className="text-[10px] uppercase tracking-wider text-sp-muted">/</span>
          <span className="text-[10px] uppercase tracking-wider text-sp-muted">{target?.root_domain || targetId}</span>
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

      <main className="p-4 max-w-7xl mx-auto space-y-4">
        {err ? <div className="text-xs text-sp-red border border-sp-red/30 bg-sp-red/10 rounded p-2">{err}</div> : null}

        <section className="border border-sp-border bg-sp-surface rounded p-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm font-bold">{target?.name || "Target"}</div>
              <div className="text-xs text-sp-muted font-mono">{target?.root_domain || targetId}</div>
            </div>

            <div className="flex flex-wrap items-end gap-2">
              <div className="flex flex-col gap-1">
                <div className="text-[10px] uppercase tracking-wider text-sp-muted">max_hosts</div>
                <input
                  value={maxHosts}
                  onChange={(e) => setMaxHosts(parseInt(e.target.value || "0", 10))}
                  className="w-24 bg-sp-bg border border-sp-border rounded px-2 py-1 text-sm outline-none focus:border-sp-cyan/60"
                />
              </div>
              <div className="flex flex-col gap-1">
                <div className="text-[10px] uppercase tracking-wider text-sp-muted">max_http</div>
                <input
                  value={maxHttpTargets}
                  onChange={(e) => setMaxHttpTargets(parseInt(e.target.value || "0", 10))}
                  className="w-24 bg-sp-bg border border-sp-border rounded px-2 py-1 text-sm outline-none focus:border-sp-cyan/60"
                />
              </div>
              <button
                onClick={startRun}
                disabled={busy !== null}
                className="px-3 py-2 rounded text-xs uppercase tracking-wider border border-sp-cyan/40 text-sp-cyan hover:bg-sp-cyan/10 disabled:opacity-60"
              >
                {busy === "start" ? "Starting..." : "Start Run"}
              </button>
              <button
                onClick={discardSelected}
                disabled={!selectedRun || !["queued", "running"].includes((selectedRun.status || "").toLowerCase()) || busy !== null}
                className="px-3 py-2 rounded text-xs uppercase tracking-wider border border-sp-border text-sp-muted hover:text-sp-text disabled:opacity-50"
              >
                Discard Run
              </button>
              <button
                onClick={verifySelected}
                disabled={!selectedRunId || busy !== null}
                className="px-3 py-2 rounded text-xs uppercase tracking-wider border border-sp-border text-sp-muted hover:text-sp-text disabled:opacity-50"
              >
                Verify Stale
              </button>
              <button
                onClick={loadAll}
                className="px-3 py-2 rounded text-xs uppercase tracking-wider border border-sp-border text-sp-muted hover:text-sp-text"
              >
                Refresh
              </button>
            </div>
          </div>
        </section>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <section className="lg:col-span-1 border border-sp-border bg-sp-surface rounded p-3">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs uppercase tracking-wider text-sp-muted">Runs</div>
              <div className="text-[10px] text-sp-muted">{runs.length}</div>
            </div>
            <div className="space-y-2 max-h-[60vh] overflow-auto pr-1">
              {runs.map((r) => (
                <button
                  key={r.id}
                  onClick={() => setSelectedRunId(r.id)}
                  className={`w-full text-left border rounded p-2 ${
                    selectedRunId === r.id ? "border-sp-cyan/50 bg-sp-bg/40" : "border-sp-border hover:bg-sp-bg/30"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-xs font-mono">{r.id.slice(0, 8)}...</div>
                    <span className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border ${badge(r.status)}`}>
                      {r.status}
                    </span>
                  </div>
                  <div className="text-[10px] text-sp-muted mt-1">
                    {r.trigger} | started {fmt(r.started_at)} | done {fmt(r.completed_at)}
                  </div>
                </button>
              ))}
              {runs.length === 0 ? <div className="text-sm text-sp-muted py-8 text-center">No runs yet.</div> : null}
            </div>
          </section>

          <section className="lg:col-span-2 space-y-4">
            <section className="border border-sp-border bg-sp-surface rounded p-3">
              <div className="flex items-center justify-between">
                <div className="text-xs uppercase tracking-wider text-sp-muted">Changes</div>
                <div className="text-[10px] text-sp-muted">{selectedRunId ? selectedRunId.slice(0, 8) : "-"}</div>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-3">
                <div className="border border-sp-border rounded p-2 bg-sp-bg/30">
                  <div className="text-[10px] text-sp-muted uppercase tracking-wider">New Assets</div>
                  <div className="text-lg text-sp-text">{changes?.counts?.new_assets ?? "-"}</div>
                </div>
                <div className="border border-sp-border rounded p-2 bg-sp-bg/30">
                  <div className="text-[10px] text-sp-muted uppercase tracking-wider">New Services</div>
                  <div className="text-lg text-sp-text">{changes?.counts?.new_services ?? "-"}</div>
                </div>
                <div className="border border-sp-border rounded p-2 bg-sp-bg/30">
                  <div className="text-[10px] text-sp-muted uppercase tracking-wider">Pending Verify</div>
                  <div className="text-lg text-sp-text">
                    {(changes?.counts?.pending_assets ?? 0) + (changes?.counts?.pending_services ?? 0)}
                  </div>
                </div>
                <div className="border border-sp-border rounded p-2 bg-sp-bg/30">
                  <div className="text-[10px] text-sp-muted uppercase tracking-wider">Closed/Unres</div>
                  <div className="text-lg text-sp-text">
                    {(changes?.counts?.confirmed_closed_assets ?? 0) +
                      (changes?.counts?.confirmed_closed_services ?? 0) +
                      (changes?.counts?.confirmed_unresolved_assets ?? 0) +
                      (changes?.counts?.confirmed_unresolved_services ?? 0)}
                  </div>
                </div>
              </div>
            </section>

            <section className="border border-sp-border bg-sp-surface rounded p-3">
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs uppercase tracking-wider text-sp-muted">Jobs (Run)</div>
                <div className="text-[10px] text-sp-muted">{jobs.length}</div>
              </div>
              <div className="overflow-auto max-h-56">
                <table className="w-full text-sm">
                  <thead className="text-[10px] uppercase tracking-wider text-sp-muted">
                    <tr className="border-b border-sp-border">
                      <th className="text-left py-2 pr-2">Type</th>
                      <th className="text-left py-2 pr-2">Status</th>
                      <th className="text-left py-2 pr-2">Attempts</th>
                      <th className="text-left py-2 pr-2">Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.map((j) => (
                      <tr key={j.id} className="border-b border-sp-border/60">
                        <td className="py-2 pr-2 font-mono">{j.type}</td>
                        <td className="py-2 pr-2">
                          <span className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border ${badge(j.status)}`}>
                            {j.status}
                          </span>
                        </td>
                        <td className="py-2 pr-2 text-sp-muted">{j.attempts}</td>
                        <td className="py-2 pr-2 text-sp-muted">{fmt(j.updated_at)}</td>
                      </tr>
                    ))}
                    {jobs.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="py-6 text-center text-sm text-sp-muted">
                          No jobs for this run.
                        </td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="border border-sp-border bg-sp-surface rounded p-3">
              <div className="text-xs uppercase tracking-wider text-sp-muted mb-2">Scans (Run)</div>
              <div className="overflow-auto max-h-56">
                <table className="w-full text-sm">
                  <thead className="text-[10px] uppercase tracking-wider text-sp-muted">
                    <tr className="border-b border-sp-border">
                      <th className="text-left py-2 pr-2">Scanner</th>
                      <th className="text-left py-2 pr-2">Target</th>
                      <th className="text-left py-2 pr-2">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runScans.map((s) => (
                      <tr key={s.id} className="border-b border-sp-border/60">
                        <td className="py-2 pr-2 font-mono">{s.scanner}</td>
                        <td className="py-2 pr-2 text-sp-muted font-mono break-all">{s.target}</td>
                        <td className="py-2 pr-2 text-sp-muted">{s.status}</td>
                      </tr>
                    ))}
                    {selectedRunId && runScans.length === 0 ? (
                      <tr>
                        <td colSpan={3} className="py-6 text-center text-sm text-sp-muted">
                          No scans recorded for this run yet.
                        </td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="border border-sp-border bg-sp-surface rounded p-3">
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs uppercase tracking-wider text-sp-muted">Findings (Run)</div>
                <div className="text-[10px] text-sp-muted">{runFindings.length}</div>
              </div>
              <div className="space-y-2 max-h-56 overflow-auto pr-1">
                {runFindings.map((f) => (
                  <div key={f.id} className="border border-sp-border rounded p-2 bg-sp-bg/30">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-sm">{f.title}</div>
                      <div className="text-[10px] uppercase tracking-wider text-sp-muted">{f.severity}</div>
                    </div>
                    <div className="text-[10px] text-sp-muted font-mono break-all">{f.url || "-"}</div>
                  </div>
                ))}
                {selectedRunId && runFindings.length === 0 ? (
                  <div className="text-sm text-sp-muted py-6 text-center">No findings for this run.</div>
                ) : null}
              </div>
            </section>
          </section>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <section className="border border-sp-border bg-sp-surface rounded p-3">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs uppercase tracking-wider text-sp-muted">Schedules</div>
              <div className="text-[10px] text-sp-muted">{schedules.length}</div>
            </div>

            <div className="grid grid-cols-2 gap-2 mb-3">
              <div className="flex flex-col gap-1">
                <div className="text-[10px] uppercase tracking-wider text-sp-muted">Interval (s)</div>
                <input
                  value={scheduleInterval}
                  onChange={(e) => setScheduleInterval(parseInt(e.target.value || "0", 10))}
                  className="bg-sp-bg border border-sp-border rounded px-2 py-1 text-sm outline-none focus:border-sp-cyan/60"
                />
              </div>
              <div className="flex items-center gap-2 pt-5">
                <input
                  type="checkbox"
                  checked={scheduleEnabled}
                  onChange={(e) => setScheduleEnabled(e.target.checked)}
                />
                <span className="text-xs text-sp-muted">Enabled</span>
              </div>
              <button
                onClick={createSchedule}
                disabled={busy !== null}
                className="col-span-2 px-3 py-2 rounded text-xs uppercase tracking-wider border border-sp-border text-sp-muted hover:text-sp-text disabled:opacity-60"
              >
                {busy === "schedule" ? "Saving..." : "Create Schedule"}
              </button>
            </div>

            <div className="space-y-2 max-h-56 overflow-auto pr-1">
              {schedules.map((s) => (
                <div key={s.id} className="border border-sp-border rounded p-2 bg-sp-bg/30">
                  <div className="flex items-center justify-between">
                    <div className="text-xs font-mono">{s.id.slice(0, 8)}...</div>
                    <span className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border ${badge(s.enabled ? "running" : "discarded")}`}>
                      {s.enabled ? "enabled" : "disabled"}
                    </span>
                  </div>
                  <div className="text-[10px] text-sp-muted mt-1">
                    every {s.interval_seconds}s | next {fmt(s.next_run_at)}
                  </div>
                </div>
              ))}
              {schedules.length === 0 ? <div className="text-sm text-sp-muted py-6 text-center">No schedules.</div> : null}
            </div>
          </section>

          <section className="border border-sp-border bg-sp-surface rounded p-3">
            <div className="text-xs uppercase tracking-wider text-sp-muted mb-2">Inventory Snapshot</div>
            <div className="grid grid-cols-2 gap-2">
              <div className="border border-sp-border rounded p-2 bg-sp-bg/30">
                <div className="text-[10px] uppercase tracking-wider text-sp-muted">Assets</div>
                <div className="text-lg">{assets.length}</div>
              </div>
              <div className="border border-sp-border rounded p-2 bg-sp-bg/30">
                <div className="text-[10px] uppercase tracking-wider text-sp-muted">Services</div>
                <div className="text-lg">{services.length}</div>
              </div>
            </div>
            <div className="text-[10px] text-sp-muted mt-3">
              Tip: inventory is global per target (not per run) in this view; use the Changes panel to see run deltas.
            </div>
          </section>
        </div>

        <section className="border border-sp-border bg-sp-surface rounded p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="text-xs uppercase tracking-wider text-sp-muted">Recon Graph</div>
            <div className="text-[10px] text-sp-muted">
              {assets.length} nodes | {edges.length} edges
            </div>
          </div>
          <ReconGraph assets={assets} edges={edges} />
        </section>
      </main>
    </div>
  );
}
