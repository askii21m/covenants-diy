// A comment box, after Unreal's: created around a selection with C, titled
// in place, coloured from a palette, resizable from any side, and moving
// it moves the nodes fully inside it (the canvas does that part, because
// it needs the other nodes). When the view is zoomed far out the title
// scales up into a bubble so it stays readable as a landmark.
import { memo, useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { NodeResizer, useViewport, type NodeProps } from "@xyflow/react";
import { useStore, type FlowNode } from "../store";
import { InlineName } from "./InlineName";

export const COMMENT_COLORS: Record<string, string> = {
  teal: "#0F766E", blue: "#2E5FA8", violet: "#7C6BAE", amber: "#B54708", rose: "#B42318", slate: "#5A6472", green: "#3F7D3A", ink: "#0E1116",
};

function CommentImpl({ id, data, selected, positionAbsoluteX, positionAbsoluteY }: NodeProps<FlowNode>) {
  const setField = useStore((s) => s.setField);
  const setSize = useStore((s) => s.setNodeSize);
  const editing = useStore((s) => s.renaming === id);
  const setRenaming = useStore((s) => s.setRenaming);
  const select = useStore((s) => s.select);
  const zoom = useViewport().zoom;
  // React Flow puts z-index -1 on a comment's wrapper so the box sits behind
  // the nodes it frames, and that wrapper is a stacking context, so nothing
  // inside it can rise above them. The bubble is a landmark and has to, so
  // it is rendered into the viewport instead, as a sibling of the nodes.
  const [layer, setLayer] = useState<HTMLElement | null>(null);
  useEffect(() => { setLayer(document.querySelector<HTMLElement>(".react-flow__viewport")); }, []);
  const color = COMMENT_COLORS[String(data.color ?? "teal")] ?? COMMENT_COLORS.teal;
  const title = String(data.name ?? "");
  // Unreal's "Show Bubble When Zoomed": below 60% a bubble floats above
  // the box, counter-scaled so the title is the same size on screen
  // however far out you are. The header itself never changes.
  const bubble = zoom < 0.6 && title && !editing ? Math.min(5, 1 / zoom) : 0;
  return (
    // React Flow does not select this node (it is marquee-proof), so a press
    // on it selects it here, in the capture phase, before the drag starts.
    <div className={`comment ${selected ? "on" : ""}`} style={{ width: Number(data.width), height: Number(data.height), ["--cm" as string]: color }}
      onMouseDownCapture={(e) => { if (e.button === 0 && !selected) select(id); }}>
      <NodeResizer isVisible={selected} minWidth={160} minHeight={80} lineClassName="cm-line" handleClassName="cm-handle"
        onResize={(_, p) => setSize(id, p.width, p.height)} />
      {/* Counter-scaled so it reads at any distance, but never wider on
          screen than the box it names: two boxes side by side would
          otherwise have their labels overlap. */}
      {bubble > 0 && layer && createPortal(
        <div className="cm-anchor" style={{ left: positionAbsoluteX, top: positionAbsoluteY, ["--cm" as string]: color }}>
          <div className="cm-bubble" style={{ transform: `scale(${bubble})`, maxWidth: Number(data.width) / bubble }}>{title}</div>
        </div>, layer)}
      <div className="cm-head">
        <InlineName className="cm-title" value={title} placeholder="Comment" editing={editing}
          onStart={() => setRenaming(id)} onCommit={(v) => { if (v != null) setField(id, "name", v); setRenaming(null); }} />
      </div>
    </div>
  );
}
export const CommentNode = memo(CommentImpl);
