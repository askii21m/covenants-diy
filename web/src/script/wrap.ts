// How a script preview renders inside a node: the block wraps at roughly
// this many characters and is clamped, so the layout and the node have to
// agree on both or a comment box is drawn around the wrong height.
// Measured: 262px of content at 7.2px a character in JetBrains Mono.
export const WRAP_COLS = 36;
export const LINE_PX = 18.6;
export const MAX_SRC_PX = 96;

export function scriptLines(src: string): number {
  return src.split("\n").reduce((t, l) => t + Math.max(1, Math.ceil(l.length / WRAP_COLS)), 0);
}
/** Rendered height of the preview, and whether it hides anything. */
export function scriptBlock(src: string): { height: number; clipped: boolean } {
  const full = scriptLines(src) * LINE_PX;
  return { height: Math.min(MAX_SRC_PX, full), clipped: full > MAX_SRC_PX + 1 };
}
