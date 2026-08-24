// The wire being dragged, in the colour of the pin it came from.
import { getBezierPath, Position, type ConnectionLineComponentProps } from "@xyflow/react";
import { findPort } from "../registry";
import { useStore } from "../store";

export function ConnectionLine({
  fromX,
  fromY,
  toX,
  toY,
  fromNode,
  fromHandle,
  connectionStatus,
}: ConnectionLineComponentProps) {
  const node = useStore((s) => s.nodes.find((n) => n.id === fromNode?.id));
  const side = fromHandle?.type === "source" ? "source" : "target";
  const type = node && fromHandle?.id ? (findPort(node.data, side, fromHandle.id)?.type ?? "any") : "any";
  const [d] = getBezierPath({
    sourceX: fromX,
    sourceY: fromY,
    sourcePosition: side === "source" ? Position.Right : Position.Left,
    targetX: toX,
    targetY: toY,
    targetPosition: side === "source" ? Position.Left : Position.Right,
  });
  return (
    <g className={`conn t-${type} ${connectionStatus ?? ""}`}>
      <path d={d} fill="none" />
      <circle cx={toX} cy={toY} r={4} />
    </g>
  );
}
