// A knot on a wire. The coloured dot is the pin, so wires meet its rim;
// the transparent ring around it is the drag area. A pin off the dot would
// leave wires ending in space; a pin over the whole dot would leave nothing
// to drag by. The dot takes the colour of whatever flows into it.
import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { useStore, wireType, type FlowNode } from "../store";

function RerouteImpl({ id, selected }: NodeProps<FlowNode>) {
  const type = useStore((s) => { const e = s.edges.find((e) => e.target === id); return e ? wireType(e, s.nodes, s.edges) : "any"; });
  const setPinMenu = useStore((s) => s.setPinMenu);
  const connecting = useStore((s) => s.connecting);
  // A knot passes anything through, so it steps back only when the drag
  // began at another node's output, which its own dot could not accept.
  const off = connecting && connecting.nodeId !== id && connecting.handleType === "target" ? " off" : "";
  const breakWires = useStore((s) => s.breakWires);
  // The dot is both pins; a right-click offers the outgoing links, since
  // the one incoming wire is the knot's own and goes with the knot.
  const menu = (e: React.MouseEvent) => { e.preventDefault(); e.stopPropagation(); setPinMenu({ nodeId: id, handleId: "out", side: "source", x: e.clientX, y: e.clientY }); };
  // Alt-click matches the menu's scope: the outgoing links. The incoming
  // wire is the knot's own; breaking it would leave the knot orphaned.
  const alt = (e: React.PointerEvent | React.MouseEvent) => { if (e.altKey && e.button === 0) { e.preventDefault(); e.stopPropagation(); breakWires(id, "out"); } };
  return (
    <div className={`rr t-${type}${off} ${selected ? "on" : ""}`}>
      <div className="rr-drag" title="drag to move" />
      <Handle type="target" position={Position.Left} id="in" className="rr-pin" />
      <Handle type="source" position={Position.Right} id="out" className="rr-pin" title="drag to wire" onContextMenu={menu} onPointerDownCapture={alt} onMouseDownCapture={alt} />
    </div>
  );
}
export const RerouteNode = memo(RerouteImpl);
