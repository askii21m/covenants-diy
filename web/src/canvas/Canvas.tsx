// The canvas: React Flow configured to behave like a production node editor,
// plus the behaviours it does not ship with. Right or middle drag pans,
// scroll zooms at the cursor, left drag box-selects, Shift adds to the
// selection, nodes snap to a 16px grid. Right-click or Tab opens the add
// menu at the cursor; dragging a wire into empty space opens it with the
// new node pre-wired. Dropping a node on a wire splices it in. Comments
// carry their contents when moved.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  MiniMap,
  SelectionMode,
  useReactFlow,
  useViewport,
  useNodesInitialized,
  type NodeTypes,
  type Edge,
  type OnConnectEnd,
  type OnReconnect,
} from "@xyflow/react";
import { useStore, isValidConnection, wireType, type FlowNode, type Pending } from "../store";
import { findPort, KINDS } from "../registry";
import { CovNode } from "../nodes/CovNode";
import { RerouteNode } from "../nodes/RerouteNode";
import { CommentNode } from "../nodes/CommentNode";
import { AddMenu, ContextMenu, type MenuItem } from "./menus";

/** Filled in by the canvas on mount. The menu bar renders outside
 *  ReactFlowProvider, so it cannot hold the instance these need. */
export const viewActions = {
  zoomIn: () => {},
  zoomOut: () => {},
  reset: () => {},
  frameAll: () => {},
  frameSelection: () => {},
};
import { ConnectionLine } from "./ConnectionLine";

const nodeTypes: NodeTypes = { cov: CovNode, reroute: RerouteNode, comment: CommentNode };
const GRID = 16;

type Menu =
  | { kind: "add"; x: number; y: number; flow: { x: number; y: number }; pending?: Pending }
  | { kind: "node"; x: number; y: number; id: string }
  | { kind: "edge"; x: number; y: number; id: string; flow: { x: number; y: number } }
  | { kind: "pane"; x: number; y: number; flow: { x: number; y: number } };

export function Canvas() {
  const nodes = useStore((s) => s.nodes);
  const rawEdges = useStore((s) => s.edges);
  const selected = useStore((s) => s.selected);
  const spliceEdge = useStore((s) => s.spliceEdge);
  const placing = useStore((s) => s.placing);
  const pinMenu = useStore((s) => s.pinMenu);
  const active = useStore((s) => s.active);
  const s = useStore.getState;
  const rf = useReactFlow();
  const showMinimap = useStore((s) => s.showMinimap);
  // The menu bar renders outside ReactFlowProvider and so cannot hold the
  // instance. The canvas leaves the three view actions here for it.
  useEffect(() => {
    viewActions.zoomIn = () => rf.zoomIn({ duration: 150 });
    viewActions.zoomOut = () => rf.zoomOut({ duration: 150 });
    viewActions.reset = () => rf.zoomTo(1, { duration: 150 });
    viewActions.frameAll = () => rf.fitView({ padding: 0.12, duration: 250 });
    viewActions.frameSelection = () => {
      const sel = useStore.getState().nodes.filter((n) => n.selected);
      rf.fitView({ nodes: sel.length ? sel : undefined, padding: 0.2, duration: 250, maxZoom: 1.25 });
    };
  }, [rf]);

  // A document that becomes active comes back at the view it was left at,
  // or, if it has never been viewed, framed on its first few real nodes
  // once React Flow has measured them. Gated on React Flow's own
  // readiness: a frame timer fires for unmeasured nodes (and never in a
  // hidden tab), and fitting unmeasured nodes yields a viewport at the
  // origin that onMoveEnd would then persist as the document's view.
  const [ready, setReady] = useState(false);
  // Only a trigger: on the render where `active` changes this still holds
  // the previous document's value, so measurement is read from React Flow
  // inside the effect.
  const initialized = useNodesInitialized();
  const viewAll = useRef(new URLSearchParams(location.search).get("view") === "all");
  const framed = useRef<string | null>(null);
  useEffect(() => {
    if (!ready || !active || framed.current === active) return;
    const v = s().view;
    const nodes = s().nodes;
    const isMeasured = (ids: string[]) => ids.every((id) => (rf.getInternalNode(id)?.measured.width ?? 0) > 0);
    if (viewAll.current) {
      if (!isMeasured(nodes.map((n) => n.id))) return;
      viewAll.current = false;
      rf.fitView({ padding: 0.04, duration: 0 });
    } else if (v) rf.setViewport(v, { duration: 0 });
    else if (!nodes.length) rf.setViewport({ x: 0, y: 0, zoom: 1 }, { duration: 0 });
    else {
      // A document of nothing but comments and knots frames all of them:
      // fitView with an empty node list matches nothing and would leave the
      // previous document's viewport in place.
      const real = nodes.filter((n) => n.data.kind !== "comment" && n.data.kind !== "reroute").slice(0, 6);
      const ids = (real.length ? real : nodes).map((n) => n.id);
      if (!isMeasured(ids)) return;
      rf.fitView({ nodes: ids.map((id) => ({ id })), padding: 0.12, maxZoom: 1, duration: 0 });
    }
    framed.current = active;
  }, [ready, initialized, active, rf, s]);
  const [menu, setMenu] = useState<Menu | null>(null);
  // The wire a user dropped in empty space, kept on screen while the add
  // menu is open, from the pin to the drop point.
  const [pendingWire, setPendingWire] = useState<{
    x1: number;
    y1: number;
    x2: number;
    y2: number;
    type: string;
    side: "source" | "target";
  } | null>(null);
  const mouse = useRef({ x: 0, y: 0 });
  const wrapper = useRef<HTMLDivElement>(null);
  const reconnected = useRef(false);
  const dragStart = useRef<{ contained: string[]; last: { x: number; y: number } } | null>(null);
  // Wire geometry sampled once when a drag starts; per-move checks are pure
  // arithmetic against it. Sampling the DOM on every move is what made
  // dragging feel laggy.
  const edgePts = useRef<Map<string, { x: number; y: number }[]> | null>(null);
  const lastSpliceCheck = useRef(0);

  // Nodes are typed by kind for React Flow; comments sit behind everything.
  const flowNodes = useMemo<FlowNode[]>(
    () =>
      nodes.map((n) => ({
        ...n,
        type: n.data.kind === "reroute" ? "reroute" : n.data.kind === "comment" ? "comment" : "cov",
        zIndex: n.data.kind === "comment" ? -1 : n.selected ? 2 : 1,
        // A knot drags by its ring; its dot is the pin.
        ...(n.data.kind === "reroute" ? { dragHandle: ".rr-drag" } : {}),
        // A comment is picked by clicking it, never swept up by a marquee over
        // the nodes inside it, so selection passes through to them.
        ...(n.data.kind === "comment" ? { selectable: false } : {}),
        ...(n.data.kind === "comment" ? { style: { width: Number(n.data.width), height: Number(n.data.height) } } : {}),
      })),
    [nodes],
  );

  // Wires carry their type as a class, and the selected node's wires lift.
  const edges = useMemo<Edge[]>(
    () =>
      rawEdges.map((e) => ({
        ...e,
        reconnectable: true,
        className: `t-${wireType(e, nodes, rawEdges)}${selected && (e.source === selected || e.target === selected) ? " hi" : ""}${spliceEdge === e.id ? " splice" : ""}`,
      })),
    [rawEdges, nodes, selected, spliceEdge],
  );

  const flowAt = useCallback((x: number, y: number) => rf.screenToFlowPosition({ x, y }), [rf]);
  const snap = (p: { x: number; y: number }) => ({
    x: Math.round(p.x / GRID) * GRID,
    y: Math.round(p.y / GRID) * GRID,
  });
  const openAdd = useCallback(
    (x: number, y: number, pending?: Pending) => setMenu({ kind: "add", x, y, flow: flowAt(x, y), pending }),
    [flowAt],
  );

  // --- placing a node attached to the cursor ---------------------------------
  const [ghost, setGhost] = useState<{ x: number; y: number } | null>(null);
  useEffect(() => {
    if (!placing) setGhost(null);
  }, [placing]);

  // --- connection dropped on empty space: add menu, pre-wired ---------------
  const onConnectEnd: OnConnectEnd = useCallback(
    (event, state) => {
      s().setConnecting(null);
      if (state.isValid || !state.fromNode || !state.fromHandle) return;
      const me = event as MouseEvent;
      const side = state.fromHandle.type === "source" ? "source" : "target";
      const handleId = state.fromHandle.id ?? "";
      const el = wrapper.current?.querySelector<HTMLElement>(
        `.react-flow__node[data-id="${CSS.escape(state.fromNode.id)}"] .react-flow__handle[data-handleid="${CSS.escape(handleId)}"]`,
      );
      const box = wrapper.current?.getBoundingClientRect();
      if (el && box) {
        const r = el.getBoundingClientRect();
        const from = s().nodes.find((n) => n.id === state.fromNode!.id);
        const type = from ? (findPort(from.data, side, handleId)?.type ?? "any") : "any";
        setPendingWire({
          x1: r.left + r.width / 2 - box.left,
          y1: r.top + r.height / 2 - box.top,
          x2: me.clientX - box.left,
          y2: me.clientY - box.top,
          type,
          side,
        });
      }
      openAdd(me.clientX, me.clientY, { nodeId: state.fromNode.id, handleId, handleType: side });
    },
    [openAdd, s],
  );
  const closeMenu = useCallback(() => {
    setMenu(null);
    setPendingWire(null);
  }, []);

  // --- reconnect: drag a wire end to another pin, or into space to delete ---
  const onReconnect: OnReconnect = useCallback(
    (oldEdge, c) => {
      reconnected.current = true;
      s().reconnect(oldEdge, c);
    },
    [s],
  );
  const onReconnectStart = useCallback(() => {
    reconnected.current = false;
  }, []);
  const onReconnectEnd = useCallback(
    (_: unknown, edge: Edge) => {
      if (!reconnected.current) s().removeEdge(edge.id);
    },
    [s],
  );

  // --- splice a dragged node into a wire; carry a comment's contents -------
  const sampleEdges = useCallback(() => {
    const map = new Map<string, { x: number; y: number }[]>();
    for (const e of rawEdges) {
      const path = wrapper.current?.querySelector<SVGPathElement>(
        `.react-flow__edge[data-id="${CSS.escape(e.id)}"] .react-flow__edge-path`,
      );
      if (!path) continue;
      const len = path.getTotalLength();
      const pts: { x: number; y: number }[] = [];
      for (let t = 0; t <= len; t += 14) {
        const p = path.getPointAtLength(t);
        pts.push({ x: p.x, y: p.y });
      }
      map.set(e.id, pts);
    }
    return map;
  }, [rawEdges]);

  const nearestEdge = useCallback((node: FlowNode): string | null => {
    if (node.data.kind === "comment" || node.data.kind === "reroute" || !edgePts.current) return null;
    const w = node.measured?.width ?? 288,
      h = node.measured?.height ?? 200;
    const cx = node.position.x + w / 2,
      cy = node.position.y + h / 2;
    let best: { id: string; d: number } | null = null;
    for (const [id, pts] of edgePts.current) {
      for (const p of pts) {
        const d = Math.hypot(p.x - cx, p.y - cy);
        if (d < 18 && (!best || d < best.d)) best = { id, d };
      }
    }
    return best?.id ?? null;
  }, []);

  const onNodeDragStart = useCallback(
    (_: unknown, node: FlowNode) => {
      // Only an unconnected node can be spliced into a wire.
      const connected = rawEdges.some((e) => e.source === node.id || e.target === node.id);
      edgePts.current =
        node.data.kind === "comment" || node.data.kind === "reroute" || connected ? null : sampleEdges();
      if (node.data.kind !== "comment" || node.data.moveContents === false) return;
      // Group Movement: everything fully inside the box at drag start comes
      // along, nested comments included. Nodes React Flow is already moving
      // (the selection) are left to it, or they would move twice.
      const w = Number(node.data.width),
        h = Number(node.data.height);
      const sizeOf = (n: FlowNode) =>
        n.data.kind === "comment"
          ? { w: Number(n.data.width), h: Number(n.data.height) }
          : { w: n.measured?.width ?? 288, h: n.measured?.height ?? 200 };
      const inside = s()
        .nodes.filter((n) => {
          if (n.id === node.id || n.selected) return false;
          const sz = sizeOf(n);
          return (
            n.position.x >= node.position.x &&
            n.position.y >= node.position.y &&
            n.position.x + sz.w <= node.position.x + w &&
            n.position.y + sz.h <= node.position.y + h
          );
        })
        .map((n) => n.id);
      dragStart.current = { contained: inside, last: { ...node.position } };
    },
    [s, rawEdges, sampleEdges],
  );
  const onNodeDrag = useCallback(
    (_: unknown, node: FlowNode) => {
      if (dragStart.current) {
        const { last, contained } = dragStart.current;
        s().moveNodes(contained, node.position.x - last.x, node.position.y - last.y);
        dragStart.current.last = { ...node.position };
        return;
      }
      if (!edgePts.current) return;
      const now = performance.now();
      if (now - lastSpliceCheck.current < 50) return;
      lastSpliceCheck.current = now;
      s().setSpliceEdge(nearestEdge(node));
    },
    [nearestEdge, s],
  );
  const onNodeDragStop = useCallback(
    (_: unknown, node: FlowNode) => {
      dragStart.current = null;
      const target = s().spliceEdge;
      s().setSpliceEdge(null);
      if (target && nearestEdge(node) === target) s().spliceNode(node.id, target);
      edgePts.current = null;
    },
    [nearestEdge, s],
  );

  // --- keyboard -------------------------------------------------------------
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      const typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);
      const mod = e.metaKey || e.ctrlKey;
      // A field owns its own Escape; the canvas only acts when nothing is focused.
      if (typing) return;
      if (e.key === "Escape") {
        if (menu) closeMenu();
        else if (s().placing) s().setPlacing(null);
        else s().deselectAll();
        return;
      }
      if (mod && e.key.toLowerCase() === "z") {
        e.preventDefault();
        if (e.shiftKey) s().redo();
        else s().undo();
        return;
      }
      if (mod && e.key.toLowerCase() === "y") {
        e.preventDefault();
        s().redo();
        return;
      }
      if (mod && e.key.toLowerCase() === "c") {
        e.preventDefault();
        s().copy();
        return;
      }
      if (mod && e.key.toLowerCase() === "v") {
        e.preventDefault();
        s().paste(snap(flowAt(mouse.current.x, mouse.current.y)));
        return;
      }
      if (mod && e.key.toLowerCase() === "d") {
        e.preventDefault();
        s().duplicate();
        return;
      }
      if (mod && e.key.toLowerCase() === "a") {
        e.preventDefault();
        s().selectAll();
        return;
      }
      if (mod) return;
      if (e.key === "Tab" || (e.shiftKey && e.key.toLowerCase() === "a")) {
        e.preventDefault();
        openAdd(mouse.current.x, mouse.current.y);
        return;
      }
      if (e.key === "Delete" || e.key === "Backspace" || e.key.toLowerCase() === "x") {
        e.preventDefault();
        s().removeSelected();
        return;
      }
      if (e.key.toLowerCase() === "f") {
        const sel = s().nodes.filter((n) => n.selected);
        rf.fitView({ nodes: sel.length ? sel : undefined, padding: 0.2, duration: 250, maxZoom: 1.25 });
        return;
      }
      if (e.key === "Home") {
        rf.fitView({ padding: 0.12, duration: 250 });
        return;
      }
      if (e.key.toLowerCase() === "c" && !e.shiftKey) {
        s().commentAroundSelection(snap(flowAt(mouse.current.x, mouse.current.y)));
        return;
      }
      if (e.key === "F2") {
        const sel = s().selected;
        if (sel) s().setRenaming(sel);
        return;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menu, openAdd, rf, flowAt, s, closeMenu]);

  // --- context menus ------------------------------------------------------------
  const nodeMenu = (id: string): MenuItem[] => {
    const n = s().nodes.find((n) => n.id === id);
    const kind = n && KINDS[n.data.kind as string];
    return [
      { label: "Rename", shortcut: "F2", onClick: () => s().setRenaming(id), disabled: kind?.kind === "reroute" },
      {
        label: n?.data.collapsed ? "Expand" : "Collapse",
        onClick: () => s().setField(id, "collapsed", !n?.data.collapsed),
        disabled: kind?.kind === "reroute" || kind?.kind === "comment",
      },
      { separator: true, label: "" },
      {
        label: "Duplicate",
        shortcut: "⌘D",
        onClick: () => {
          s().select(id);
          s().duplicate();
        },
      },
      {
        label: "Copy",
        shortcut: "⌘C",
        onClick: () => {
          s().select(id);
          s().copy();
        },
      },
      {
        label: "Break all wires",
        onClick: () => s().breakWires(id),
        disabled: !s().edges.some((e) => e.source === id || e.target === id),
      },
      { separator: true, label: "" },
      {
        label: "Delete",
        shortcut: "⌫",
        onClick: () => {
          s().select(id);
          s().removeSelected();
        },
      },
    ];
  };
  const edgeMenu = (id: string, flow: { x: number; y: number }): MenuItem[] => [
    { label: "Add reroute", shortcut: "dbl-click", onClick: () => s().insertReroute(id, flow) },
    { label: "Delete wire", onClick: () => s().removeEdge(id) },
  ];
  /** Right-click on a pin: break one wire, or any of several, or all of
   *  them; an unwired input can have a node added to feed it. */
  const pinMenuItems = (m: NonNullable<typeof pinMenu>): MenuItem[] => {
    const { nodeId, handleId, side } = m;
    const wires = s().edges.filter((e) =>
      side === "source"
        ? e.source === nodeId && e.sourceHandle === handleId
        : e.target === nodeId && e.targetHandle === handleId,
    );
    const nameOf = (id: string) => {
      const n = s().nodes.find((n) => n.id === id);
      return n ? (n.data.kind === "reroute" ? "knot" : String(n.data.name || n.data.kind)) : id;
    };
    const portOf = (id: string, handle: string | null | undefined, which: "source" | "target") => {
      const n = s().nodes.find((n) => n.id === id);
      return (n && findPort(n.data, which, handle ?? "")?.label) || handle || "";
    };
    const isKnot = (id: string) => s().nodes.find((n) => n.id === id)?.data.kind === "reroute";
    const other = (e: Edge) =>
      side === "source"
        ? isKnot(e.target)
          ? "knot"
          : `${nameOf(e.target)} · ${portOf(e.target, e.targetHandle, "target")}`
        : isKnot(e.source)
          ? "knot"
          : `${nameOf(e.source)} · ${portOf(e.source, e.sourceHandle, "source")}`;
    const items: MenuItem[] = [];
    if (wires.length === 1)
      items.push({
        label: `Break link to ${other(wires[0])}`,
        shortcut: "alt-click",
        onClick: () => s().removeEdge(wires[0].id),
      });
    if (wires.length > 1) {
      items.push({
        label: `Break all ${wires.length} links`,
        shortcut: "alt-click",
        onClick: () => s().breakWires(nodeId, handleId),
      });
      items.push({ label: "Break link to", heading: true });
      for (const e of wires) items.push({ label: other(e), onClick: () => s().removeEdge(e.id) });
    }
    if (!wires.length) items.push({ label: "No links", disabled: true });
    items.push({ separator: true, label: "" });
    items.push({
      label: side === "target" ? "Add a node feeding this pin…" : "Add a node fed by this pin…",
      onClick: () =>
        setTimeout(() => {
          const n = s().nodes.find((n) => n.id === nodeId);
          const el = document.querySelector(
            `[data-id="${nodeId}"] [data-handleid="${handleId}"]`,
          ) as HTMLElement | null;
          const r = el?.getBoundingClientRect();
          const at = r
            ? { x: side === "source" ? r.right + 40 : r.left - 40, y: r.top + r.height / 2 }
            : { x: m.x, y: m.y };
          if (n) openAdd(at.x, at.y, { nodeId, handleId, handleType: side });
        }, 0),
    });
    return items;
  };
  const paneMenu = (x: number, y: number, flow: { x: number; y: number }): MenuItem[] => [
    { label: "Add node…", shortcut: "Tab", onClick: () => setTimeout(() => openAdd(x, y), 0) },
    { label: "Paste", shortcut: "⌘V", onClick: () => s().paste(snap(flow)), disabled: !s().clipboard },
    { label: "Select all", shortcut: "⌘A", onClick: () => s().selectAll() },
    { separator: true, label: "" },
    { label: "Frame all", shortcut: "Home", onClick: () => rf.fitView({ padding: 0.12, duration: 250 }) },
  ];

  const zoom = useViewport().zoom;
  const pendingPort =
    menu?.kind === "add" && menu.pending
      ? (() => {
          const n = s().nodes.find((n) => n.id === menu.pending!.nodeId);
          return n ? findPort(n.data, menu.pending!.handleType, menu.pending!.handleId) : undefined;
        })()
      : undefined;

  return (
    <div
      className={`cv-wrap ${placing ? "placing" : ""}`}
      ref={wrapper}
      onMouseMove={(e) => {
        mouse.current = { x: e.clientX, y: e.clientY };
        if (placing) setGhost({ x: e.clientX, y: e.clientY });
      }}
      onMouseLeave={() => setGhost(null)}
    >
      <ReactFlow
        nodes={flowNodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={useStore((st) => st.onNodesChange)}
        onEdgesChange={useStore((st) => st.onEdgesChange)}
        onConnect={useStore((st) => st.onConnect)}
        onConnectEnd={onConnectEnd}
        isValidConnection={isValidConnection}
        onConnectStart={(_, p) =>
          s().setConnecting(
            p.nodeId && p.handleId && p.handleType
              ? { nodeId: p.nodeId, handleId: p.handleId, handleType: p.handleType }
              : null,
          )
        }
        onReconnect={onReconnect}
        onReconnectStart={onReconnectStart}
        onReconnectEnd={onReconnectEnd}
        edgesReconnectable
        reconnectRadius={18}
        connectionLineComponent={ConnectionLine}
        onNodeClick={(_, n) => s().select(n.id)}
        onInit={() => setReady(true)}
        onMoveEnd={(_, v) => s().setView(v)}
        onNodeDoubleClick={(_, n) => {
          if (n.data.kind !== "reroute") s().setRenaming(n.id);
        }}
        onPaneClick={(e) => {
          if (placing) {
            s().addNodeAt(placing, snap({ ...flowAt(e.clientX, e.clientY) }));
            return;
          }
          s().deselectAll();
        }}
        onPaneContextMenu={(e) => {
          e.preventDefault();
          const me = e as unknown as MouseEvent;
          setMenu({ kind: "pane", x: me.clientX, y: me.clientY, flow: flowAt(me.clientX, me.clientY) });
        }}
        onNodeContextMenu={(e, n) => {
          e.preventDefault();
          s().select(n.id);
          setMenu({ kind: "node", x: e.clientX, y: e.clientY, id: n.id });
        }}
        onEdgeContextMenu={(e, ed) => {
          e.preventDefault();
          setMenu({ kind: "edge", x: e.clientX, y: e.clientY, id: ed.id, flow: flowAt(e.clientX, e.clientY) });
        }}
        onEdgeDoubleClick={(e, ed) => s().insertReroute(ed.id, flowAt(e.clientX, e.clientY))}
        onNodeDragStart={onNodeDragStart}
        onNodeDrag={onNodeDrag}
        onNodeDragStop={onNodeDragStop}
        onDrop={(e) => {
          e.preventDefault();
          const kind = e.dataTransfer.getData("application/covenants-kind");
          if (kind) s().addNodeAt(kind, snap(flowAt(e.clientX, e.clientY)));
        }}
        onDragOver={(e) => {
          e.preventDefault();
          e.dataTransfer.dropEffect = "move";
        }}
        panOnDrag={[1, 2]}
        panActivationKeyCode="Space"
        selectionOnDrag
        selectionMode={SelectionMode.Partial}
        multiSelectionKeyCode="Shift"
        zoomOnScroll
        zoomOnPinch
        panOnScroll={false}
        zoomOnDoubleClick={false}
        preventScrolling
        snapToGrid
        snapGrid={[GRID, GRID]}
        minZoom={0.2}
        maxZoom={2}
        deleteKeyCode={null}
        selectionKeyCode={null}
        elevateNodesOnSelect={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background id="minor" variant={BackgroundVariant.Lines} gap={GRID} lineWidth={1} color="#ECEEF1" />
        <Background id="major" variant={BackgroundVariant.Lines} gap={GRID * 5} lineWidth={1} color="#DFE3E8" />
        {showMinimap && (
          <MiniMap
            pannable
            zoomable
            nodeColor={(n) => (n.type === "comment" ? "#E4E7EC" : "#C9D0D9")}
            maskColor="rgba(244,245,247,.72)"
          />
        )}
      </ReactFlow>

      {pendingWire && (
        <svg className={`pending-wire t-${pendingWire.type}`} aria-hidden>
          <path d={pendingPath(pendingWire)} />
          <circle cx={pendingWire.x2} cy={pendingWire.y2} r={4} />
        </svg>
      )}

      <div className="zoom-readout" title="scroll to zoom · F frames the selection · Home frames all">
        {Math.round(zoom * 100)}%
      </div>

      {placing && ghost && (
        <div className="ghost" style={{ left: ghost.x, top: ghost.y }}>
          <span className="k">{KINDS[placing]?.category}</span> {KINDS[placing]?.label}
          <span className="hint">click to place · Esc to cancel</span>
        </div>
      )}

      {menu?.kind === "add" && (
        <AddMenu
          x={menu.x}
          y={menu.y}
          pendingPort={pendingPort}
          pendingSide={menu.pending?.handleType}
          onPick={(kind) => {
            // Place so the node's header sits under the cursor; when wiring
            // from a pin, shift up so the first pin lands near the drop.
            const p = snap({ x: menu.flow.x, y: menu.flow.y - (menu.pending ? 56 : 16) });
            s().addNodeAt(kind, p, menu.pending);
            closeMenu();
          }}
          onClose={closeMenu}
        />
      )}
      {menu?.kind === "node" && (
        <ContextMenu x={menu.x} y={menu.y} items={nodeMenu(menu.id)} onClose={() => setMenu(null)} />
      )}
      {menu?.kind === "edge" && (
        <ContextMenu x={menu.x} y={menu.y} items={edgeMenu(menu.id, menu.flow)} onClose={() => setMenu(null)} />
      )}
      {menu?.kind === "pane" && (
        <ContextMenu x={menu.x} y={menu.y} items={paneMenu(menu.x, menu.y, menu.flow)} onClose={() => setMenu(null)} />
      )}
      {pinMenu && (
        <ContextMenu x={pinMenu.x} y={pinMenu.y} items={pinMenuItems(pinMenu)} onClose={() => s().setPinMenu(null)} />
      )}
    </div>
  );
}

function pendingPath(w: { x1: number; y1: number; x2: number; y2: number; side: "source" | "target" }): string {
  const dx = Math.max(40, Math.abs(w.x2 - w.x1) / 2) * (w.side === "source" ? 1 : -1);
  return `M ${w.x1} ${w.y1} C ${w.x1 + dx} ${w.y1}, ${w.x2 - dx} ${w.y2}, ${w.x2} ${w.y2}`;
}

export type { FlowNode };
