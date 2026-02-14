"use client";

import CytoscapeComponent from "react-cytoscapejs";
import { useEffect, useMemo, useRef, useState } from "react";

type Asset = { id: string; type: string; normalized: string; value?: string; status?: string };
type Edge = { id: string; from_asset_id: string; to_asset_id: string; rel_type: string };

export function ReconGraph({ assets, edges }: { assets: Asset[]; edges: Edge[] }) {
  const cyRef = useRef<any>(null);
  const [selected, setSelected] = useState<any>(null);
  const [layoutName, setLayoutName] = useState<"cose" | "breadthfirst" | "concentric" | "circle" | "grid">("cose");
  const [animate, setAnimate] = useState(false);
  const [showLabels, setShowLabels] = useState(true);
  const [coseRepulsion, setCoseRepulsion] = useState(9000);
  const [spacingFactor, setSpacingFactor] = useState(1.3);

  const { elements, style } = useMemo(() => {
    const nodeById = new Map<string, Asset>();
    for (const a of assets) nodeById.set(a.id, a);

    const els: any[] = [];
    for (const a of assets) {
      const label = a.normalized || a.value || a.id;
      els.push({
        data: { id: a.id, label, type: a.type, status: a.status || "active" },
      });
    }

    for (const e of edges) {
      // Skip edges that refer to missing nodes
      if (!nodeById.has(e.from_asset_id) || !nodeById.has(e.to_asset_id)) continue;
      els.push({
        data: {
          id: e.id,
          source: e.from_asset_id,
          target: e.to_asset_id,
          rel: e.rel_type,
        },
      });
    }

    const commonLabel = showLabels ? "data(label)" : "";
    const sty: any[] = [
      {
        selector: "node",
        style: {
          "background-color": "#00e5ff",
          label: commonLabel,
          color: "#e8f0ff",
          "font-size": 9,
          "text-wrap": "ellipsis",
          "text-max-width": 160,
          "text-outline-color": "#0a0f1f",
          "text-outline-width": 2,
          "border-width": 1,
          "border-color": "rgba(255,255,255,0.12)",
          "min-zoomed-font-size": 6,
          width: 22,
          height: 22,
        },
      },
      {
        selector: 'node[type = "subdomain"]',
        style: { "background-color": "#00e5ff", shape: "round-rectangle", width: 26, height: 18 },
      },
      {
        selector: 'node[type = "ip"]',
        style: { "background-color": "#00ff88", shape: "ellipse", width: 20, height: 20 },
      },
      {
        selector: 'node[type = "url"]',
        style: { "background-color": "#ffb020", shape: "hexagon", width: 24, height: 24 },
      },
      {
        selector: 'node[status = "stale"]',
        style: { "border-color": "rgba(255,176,32,0.65)", "border-width": 2 },
      },
      {
        selector: 'node[status = "closed"]',
        style: { "background-color": "#ff3355" },
      },
      {
        selector: 'node[status = "unresolved"]',
        style: { "background-color": "#9aa3b2" },
      },
      {
        selector: "edge",
        style: {
          width: 1.2,
          "line-color": "rgba(232,240,255,0.18)",
          "target-arrow-color": "rgba(232,240,255,0.18)",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: showLabels ? "data(rel)" : "",
          color: "rgba(232,240,255,0.45)",
          "font-size": 8,
          "text-outline-color": "#0a0f1f",
          "text-outline-width": 2,
        },
      },
      {
        selector: ":selected",
        style: { "border-color": "rgba(0,229,255,0.9)", "border-width": 3 },
      },
    ];

    return { elements: els, style: sty };
  }, [assets, edges, showLabels]);

  const layout = useMemo(() => {
    if (layoutName === "cose") {
      return {
        name: "cose",
        animate,
        fit: false,
        padding: 30,
        nodeRepulsion: coseRepulsion,
        idealEdgeLength: 90,
        gravity: 1.0,
        randomize: true,
      };
    }
    if (layoutName === "breadthfirst") {
      return {
        name: "breadthfirst",
        animate,
        fit: false,
        padding: 30,
        directed: true,
        spacingFactor,
      };
    }
    if (layoutName === "concentric") {
      return {
        name: "concentric",
        animate,
        fit: false,
        padding: 30,
        minNodeSpacing: 30,
        spacingFactor,
      };
    }
    if (layoutName === "circle") {
      return { name: "circle", animate, fit: false, padding: 30, spacingFactor };
    }
    return { name: "grid", animate, fit: false, padding: 30, spacingFactor, avoidOverlap: true };
  }, [layoutName, animate, coseRepulsion, spacingFactor]);

  function runLayout(opts?: { fit?: boolean }) {
    const cy = cyRef.current;
    if (!cy) return;
    // Stop any in-flight layouts before starting a new one.
    try {
      cy.stop();
    } catch {}
    const l = cy.layout(layout);
    l.run();
    if (opts?.fit) {
      // Fit after a short delay to allow positions to settle.
      setTimeout(() => {
        try {
          cy.fit(undefined, 30);
        } catch {}
      }, 50);
    }
  }

  function fit() {
    const cy = cyRef.current;
    if (!cy) return;
    cy.fit(undefined, 30);
  }

  function center() {
    const cy = cyRef.current;
    if (!cy) return;
    cy.center();
  }

  function resetZoom() {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom(1);
    cy.center();
  }

  useEffect(() => {
    // When data changes, run a layout and fit so nodes don't pile up.
    runLayout({ fit: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [elements.length, edges.length, layoutName]);

  useEffect(() => {
    // Re-run layout if layout knobs change.
    runLayout({ fit: false });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [animate, coseRepulsion, spacingFactor, showLabels]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 border border-sp-border rounded bg-sp-bg/30 p-2">
        <div className="text-[10px] uppercase tracking-wider text-sp-muted mr-1">Layout</div>
        <select
          value={layoutName}
          onChange={(e) => setLayoutName(e.target.value as any)}
          className="bg-sp-bg border border-sp-border rounded px-2 py-1 text-xs text-sp-text outline-none focus:border-sp-cyan/60"
        >
          <option value="cose">Force (cose)</option>
          <option value="breadthfirst">Tree (breadthfirst)</option>
          <option value="concentric">Concentric</option>
          <option value="circle">Circle</option>
          <option value="grid">Grid</option>
        </select>

        <button
          onClick={() => runLayout({ fit: true })}
          className="px-2 py-1 rounded text-[10px] uppercase tracking-wider border border-sp-border text-sp-muted hover:text-sp-text"
        >
          Relayout
        </button>
        <button
          onClick={fit}
          className="px-2 py-1 rounded text-[10px] uppercase tracking-wider border border-sp-border text-sp-muted hover:text-sp-text"
        >
          Fit
        </button>
        <button
          onClick={center}
          className="px-2 py-1 rounded text-[10px] uppercase tracking-wider border border-sp-border text-sp-muted hover:text-sp-text"
        >
          Center
        </button>
        <button
          onClick={resetZoom}
          className="px-2 py-1 rounded text-[10px] uppercase tracking-wider border border-sp-border text-sp-muted hover:text-sp-text"
        >
          Reset Zoom
        </button>

        <label className="ml-2 flex items-center gap-2 text-xs text-sp-muted">
          <input type="checkbox" checked={animate} onChange={(e) => setAnimate(e.target.checked)} />
          Animate
        </label>
        <label className="flex items-center gap-2 text-xs text-sp-muted">
          <input type="checkbox" checked={showLabels} onChange={(e) => setShowLabels(e.target.checked)} />
          Labels
        </label>

        {layoutName === "cose" ? (
          <div className="flex items-center gap-2 ml-2">
            <div className="text-[10px] uppercase tracking-wider text-sp-muted">Spread</div>
            <input
              type="range"
              min={2000}
              max={25000}
              step={500}
              value={coseRepulsion}
              onChange={(e) => setCoseRepulsion(parseInt(e.target.value, 10))}
            />
            <div className="text-[10px] text-sp-muted w-10 text-right">{Math.round(coseRepulsion / 1000)}k</div>
          </div>
        ) : (
          <div className="flex items-center gap-2 ml-2">
            <div className="text-[10px] uppercase tracking-wider text-sp-muted">Spacing</div>
            <input
              type="range"
              min={0.6}
              max={3.0}
              step={0.1}
              value={spacingFactor}
              onChange={(e) => setSpacingFactor(parseFloat(e.target.value))}
            />
            <div className="text-[10px] text-sp-muted w-10 text-right">{spacingFactor.toFixed(1)}x</div>
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-2 text-[10px] text-sp-muted">
        <div className="flex items-center gap-2 border border-sp-border rounded bg-sp-bg/30 px-2 py-1">
          <span className="inline-block w-3 h-3 rounded-sm bg-[#00e5ff]" />
          Subdomain
        </div>
        <div className="flex items-center gap-2 border border-sp-border rounded bg-sp-bg/30 px-2 py-1">
          <span className="inline-block w-3 h-3 rounded-full bg-[#00ff88]" />
          IP
        </div>
        <div className="flex items-center gap-2 border border-sp-border rounded bg-sp-bg/30 px-2 py-1">
          <span className="inline-block w-3 h-3 bg-[#ffb020]" style={{ clipPath: "polygon(25% 0,75% 0,100% 50%,75% 100%,25% 100%,0 50%)" }} />
          URL
        </div>
        <div className="flex items-center gap-2 border border-sp-border rounded bg-sp-bg/30 px-2 py-1">
          <span className="inline-block w-3 h-3 rounded bg-[#0a0f1f] border-2 border-[rgba(255,176,32,0.65)]" />
          Stale (needs verify)
        </div>
        <div className="flex items-center gap-2 border border-sp-border rounded bg-sp-bg/30 px-2 py-1">
          <span className="inline-block w-3 h-3 rounded bg-[#ff3355]" />
          Closed
        </div>
        <div className="flex items-center gap-2 border border-sp-border rounded bg-sp-bg/30 px-2 py-1">
          <span className="inline-block w-3 h-3 rounded bg-[#9aa3b2]" />
          Unresolved
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
      <div className="lg:col-span-2 border border-sp-border rounded bg-sp-bg/30 overflow-hidden">
        <CytoscapeComponent
          elements={elements}
          style={{ width: "100%", height: "460px" }}
          layout={layout}
          stylesheet={style}
          cy={(cy: any) => {
            cyRef.current = cy;
            cy.on("tap", "node", (evt: any) => setSelected(evt.target.data()));
            cy.on("tap", "edge", (evt: any) => setSelected(evt.target.data()));
            cy.on("tap", (evt: any) => {
              if (evt.target === cy) setSelected(null);
            });
            // Initial layout+fit on mount
            setTimeout(() => {
              try {
                runLayout({ fit: true });
              } catch {}
            }, 0);
          }}
        />
      </div>

      <div className="border border-sp-border rounded bg-sp-bg/30 p-2">
        <div className="text-[10px] uppercase tracking-wider text-sp-muted mb-2">Selection</div>
        {!selected ? (
          <div className="text-xs text-sp-muted">Click a node or edge.</div>
        ) : (
          <pre className="text-[11px] text-sp-text whitespace-pre-wrap break-words">{JSON.stringify(selected, null, 2)}</pre>
        )}
      </div>
    </div>
    </div>
  );
}
