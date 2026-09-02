import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth, isUnauthorized } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import { useToast } from "../components/Toast";
import { ApiError } from "../api/client";
import { getBlastRadius, getDownstream, getGraph } from "../api/endpoints";
import type { BlastRadiusResponse, GraphNode, GraphResponse } from "../api/types";
import RotateDialog from "../components/RotateDialog";
import DestroyFlowDialog from "../components/DestroyFlowDialog";
import { STATE_DOT } from "../lib/ui";

interface Positioned extends GraphNode {
  x: number;
  y: number;
}

function layout(graph: GraphResponse): Positioned[] {
  const keks = graph.nodes.filter((n) => n.type === "kek");
  const subjectKeys = graph.nodes.filter((n) => n.type === "subject_key");
  const width = Math.max(900, keks.length * 140);
  const positions: Positioned[] = [];

  keks.forEach((k, i) => {
    positions.push({ ...k, x: ((i + 1) / (keks.length + 1)) * width, y: 90 });
  });

  const byParent = new Map<string, GraphNode[]>();
  for (const sk of subjectKeys) {
    const list = byParent.get(sk.parentId ?? "") ?? [];
    list.push(sk);
    byParent.set(sk.parentId ?? "", list);
  }
  for (const kek of keks) {
    const children = byParent.get(kek.id) ?? [];
    const kekPos = positions.find((p) => p.id === kek.id)!;
    children.forEach((child, i) => {
      const spread = Math.min(children.length, 24);
      const col = i % spread;
      const row = Math.floor(i / spread);
      positions.push({
        ...child,
        x: kekPos.x - (spread - 1) * 22 + col * 44,
        y: 260 + row * 60,
      });
    });
  }
  return positions;
}

export default function KeyMap() {
  const { hasScope, reportUnauthorized } = useAuth();
  const { t } = useLocale();
  const toast = useToast();

  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hoverId, setHoverId] = useState<string | null>(null);
  const [downstream, setDownstream] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [blast, setBlast] = useState<BlastRadiusResponse | null>(null);
  const [scale, setScale] = useState(1);
  const [rotating, setRotating] = useState<string | null>(null);
  const [destroying, setDestroying] = useState<string | null>(null);

  useEffect(() => {
    getGraph()
      .then(setGraph)
      .catch((err) => {
        if (isUnauthorized(err)) return reportUnauthorized();
        setError(err instanceof ApiError ? err.message : t("common.error_generic"));
      });
  }, [reportUnauthorized, t]);

  const positioned = useMemo(() => (graph ? layout(graph) : []), [graph]);
  const byId = useMemo(() => new Map(positioned.map((p) => [p.id, p])), [positioned]);

  const onHover = useCallback(async (id: string | null) => {
    setHoverId(id);
    if (!id) return setDownstream(new Set());
    try {
      const res = await getDownstream(id);
      setDownstream(new Set(res.descendantIds));
    } catch {
      setDownstream(new Set());
    }
  }, []);

  async function onSelect(node: GraphNode) {
    setSelected(node);
    setBlast(null);
    try {
      setBlast(await getBlastRadius(node.id));
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  if (error) return <p style={{ color: "#d97878" }}>{error}</p>;
  if (!graph) return <p className="text-muted">{t("common.loading")}</p>;

  const width = Math.max(900, positioned.reduce((m, p) => Math.max(m, p.x + 60), 0));

  return (
    <div className="kr-map-wrap">
      <svg className="kr-map-svg" viewBox={`0 0 ${width} 480`} role="img">
        <g style={{ transform: `scale(${scale})`, transformOrigin: "center top" }}>
          {graph.edges.map((e) => {
            const s = byId.get(e.source);
            const target = byId.get(e.target);
            if (!s || !target) return null;
            const lit = hoverId === e.source || downstream.has(e.target);
            return (
              <line
                key={`${e.source}-${e.target}`}
                className={`kr-map-edge${lit ? " kr-edge-lit" : ""}`}
                x1={s.x} y1={s.y} x2={target.x} y2={target.y}
              />
            );
          })}
          {positioned.map((n) => {
            const lit = n.id === hoverId || downstream.has(n.id);
            return (
              <g
                key={n.id}
                className="kr-map-node"
                transform={`translate(${n.x},${n.y})`}
                onMouseEnter={() => void onHover(n.id)}
                onMouseLeave={() => void onHover(null)}
                onClick={() => void onSelect(n)}
              >
                <circle
                  r={n.type === "kek" ? 14 : 7}
                  fill={STATE_DOT[n.state] ?? "#595d6c"}
                  stroke={lit || selected?.id === n.id ? "var(--color-accent)" : "transparent"}
                  strokeWidth={2}
                />
                {n.type === "kek" && <text className="kr-map-node-label" y={-20} textAnchor="middle">{n.id}</text>}
              </g>
            );
          })}
        </g>
      </svg>

      <div className="kr-map-legend">
        <strong>{t("map.legend")}</strong>
        {Object.entries(STATE_DOT).map(([state, color]) => (
          <span key={state} className="kr-row"><span className="kr-dot" style={{ background: color }} /> {state}</span>
        ))}
      </div>

      <div className="kr-map-zoom">
        <button type="button" className="btn btn-secondary btn-icon" onClick={() => setScale((s) => Math.min(2, s + 0.2))}>{t("map.zoom_in")}</button>
        <button type="button" className="btn btn-secondary btn-icon" onClick={() => setScale((s) => Math.max(0.4, s - 0.2))}>{t("map.zoom_out")}</button>
        <button type="button" className="btn btn-secondary" onClick={() => setScale(1)}>{t("map.fit")}</button>
      </div>

      {selected && (
        <div className="card elev-md kr-map-inspector">
          <div className="kr-row-between">
            <span className="card-title mono-ltr" style={{ fontSize: 13 }}>{selected.id}</span>
            <button type="button" className="btn btn-ghost btn-icon" onClick={() => setSelected(null)}>×</button>
          </div>
          <div className="text-muted" style={{ fontSize: 12 }}>{selected.type} · {selected.state}</div>
          <div className="text-muted" style={{ fontSize: 12 }}>dependents: {selected.dependentCount}</div>
          {blast && (
            <div className="text-muted" style={{ fontSize: 12 }}>
              {t("map.blast_radius")}: {blast.recordCount} records / {blast.downstreamKeyCount} keys
            </div>
          )}
          <div className="kr-row">
            {selected.type === "kek" && selected.state === "active" && hasScope("rotate") && (
              <button type="button" className="btn btn-ghost" onClick={() => setRotating(selected.id)}>{t("keys.action.rotate")}</button>
            )}
            {(selected.state === "deprecated" || selected.state === "revoked") && hasScope("destroy") && (
              <button type="button" className="btn btn-ghost" onClick={() => setDestroying(selected.id)}>{t("keys.action.destroy")}</button>
            )}
          </div>
        </div>
      )}

      {rotating && (
        <RotateDialog keyId={rotating} onClose={() => setRotating(null)} onDone={() => { setRotating(null); void getGraph().then(setGraph); }} />
      )}
      {destroying && (
        <DestroyFlowDialog mode="key" targetId={destroying} onClose={() => setDestroying(null)} onDone={() => void getGraph().then(setGraph)} />
      )}
    </div>
  );
}
