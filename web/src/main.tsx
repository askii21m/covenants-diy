import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { wasmReady } from "./engine";
import { savedLayout, useStore } from "./store";
import { apply as applyTheme } from "./theme";
import "./app.css";

// Before anything renders, so the editor never appears in one palette and
// then switches to the other.
applyTheme(savedLayout().theme);

// Dev affordance: the live store, for scripting the app from the console.
// It is the raw zustand store: setState bypasses stash() and commit(), so
// set `active` or `nodes` through the actions (switchDoc, newDoc, addNode)
// or the next autosave writes the wrong document.
if (import.meta.env.DEV) (window as unknown as { covenants: unknown }).covenants = useStore;

wasmReady.then(() => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
});
