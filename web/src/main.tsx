import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { wasmReady } from "./engine";
import { useStore } from "./store";
import "./app.css";


// Dev affordance: the live store, for scripting the app from the console.
// It is the raw zustand store: setState bypasses stash() and commit(), so
// set `active` or `nodes` through the actions (switchDoc, newDoc, addNode)
// or the next autosave writes the wrong document.
if (import.meta.env.DEV) (window as unknown as { covenants: unknown }).covenants = useStore;

wasmReady.then(() => {
  createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
});
