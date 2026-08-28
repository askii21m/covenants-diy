import { useEffect, useState } from "react";

/** Light, dark, or whatever the machine is set to. */
export type Theme = "system" | "light" | "dark";

export const THEMES: Theme[] = ["system", "light", "dark"];

const QUERY = "(prefers-color-scheme: dark)";

/** Which of the two palettes a setting means right now. */
export function resolve(theme: Theme): "light" | "dark" {
  if (theme !== "system") return theme;
  return window.matchMedia(QUERY).matches ? "dark" : "light";
}

/** Stamped on the root element, where the stylesheet reads it. Applied
 *  before the first render so the editor never paints one palette and then
 *  the other. */
export function apply(theme: Theme): void {
  document.documentElement.dataset.theme = resolve(theme);
}

/** Calls back when the machine's own setting changes, which only moves the
 *  page while it is following along. */
export function watchSystem(onChange: () => void): () => void {
  const q = window.matchMedia(QUERY);
  q.addEventListener("change", onChange);
  return () => q.removeEventListener("change", onChange);
}

/** The palette in force, for the parts that take a colour mode as a value
 *  rather than reading the stylesheet. */
export function useResolved(theme: Theme): "light" | "dark" {
  const [mode, setMode] = useState(() => resolve(theme));
  useEffect(() => {
    const sync = () => setMode(resolve(theme));
    sync();
    if (theme !== "system") return;
    return watchSystem(sync);
  }, [theme]);
  return mode;
}
