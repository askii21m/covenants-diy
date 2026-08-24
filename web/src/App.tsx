import { useCallback, useEffect, useRef, useState } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useStore, savedSession, sanitizeFlow, backup, rawSession, type Flow } from "./store";
import { Canvas } from "./canvas/Canvas";
import { ContextMenu, type MenuItem } from "./canvas/menus";
import { viewActions } from "./canvas/Canvas";
import { Library } from "./panels/Library";
import { Detail } from "./panels/Detail";
import { InlineName } from "./nodes/InlineName";
import { EXAMPLES, EXAMPLE_GROUPS } from "./examples";
import { shortLink, decodeFlow, fetchShared, fragmentOnUrl, idOnUrl, type SharedDoc } from "./share";
import { NETWORKS, RULESETS } from "./engine";

/** A flow file: the document's flow, its name, and the view it was left
 *  at. Older files have no name and take the file's. */
type FlowFile = Partial<Flow> & { name?: string; view?: { x: number; y: number; zoom: number } | null };

/** Opening things: a blank document, an example, or a file. Each becomes
 *  a new tab; the canvas frames it when it becomes active. */
function useOpeners() {
  const newDoc = useStore((s) => s.newDoc);
  const select = useStore((s) => s.select);
  const openBlank = useCallback(() => newDoc("untitled"), [newDoc]);
  const openExample = useCallback(
    (key: string) => {
      const ex = EXAMPLES[key];
      if (!ex) return;
      const f = ex.build();
      newDoc(ex.name, f);
      // Ids are minted afresh per document, so the selection is by name.
      const hot = f.select && useStore.getState().nodes.find((n) => n.data.name === f.select);
      if (hot) select(hot.id);
    },
    [newDoc, select],
  );
  const openFile = useCallback(
    async (file: File | undefined) => {
      if (!file) return;
      let parsed: FlowFile | null, raw: unknown;
      try {
        raw = JSON.parse(await file.text());
        parsed = sanitizeFlow(raw);
      } catch {
        return false;
      }
      if (!parsed) return false;
      newDoc(parsed.name || file.name.replace(/\.covenants\.json$|\.json$/i, "") || "untitled", parsed);
      const v = (raw as FlowFile).view;
      if (v && [v.x, v.y, v.zoom].every(Number.isFinite) && v.zoom > 0)
        useStore.getState().setView({ x: v.x, y: v.y, zoom: v.zoom });
      return true;
    },
    [newDoc],
  );
  return { openBlank, openExample, openFile };
}

type MenuName = "file" | "edit" | "view" | "new";
type OpenMenu = (which: MenuName, trigger: HTMLElement) => void;

/** Writes the active document out as a file. */
function exportJson() {
  const s = useStore.getState();
  const name = s.docs.find((d) => d.id === s.active)?.name || "untitled";
  // React Flow's runtime fields stay out of the file; a stale `measured`
  // from another zoom would mislead comment boxes before the first layout.
  const nodes = s.nodes.map(({ measured: _m, dragging: _d, selected: _s, ...n }) => n);
  const file: FlowFile = { name, nodes, edges: s.edges, network: s.network, ruleset: s.ruleset, view: s.view };
  const blob = new Blob([JSON.stringify(file, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${name.replace(/[^\w.-]+/g, "_")}.covenants.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function TopBar({ openMenu, open }: { openMenu: OpenMenu; open: MenuName | null }) {
  const network = useStore((s) => s.network);
  const ruleset = useStore((s) => s.ruleset);
  const setNetwork = useStore((s) => s.setNetwork);
  const setRuleset = useStore((s) => s.setRuleset);
  const refs = {
    file: useRef<HTMLButtonElement>(null),
    edit: useRef<HTMLButtonElement>(null),
    view: useRef<HTMLButtonElement>(null),
  };
  return (
    <header className="top">
      <div className="mark">
        {/* The favicon, inline so it takes the header's own scale. */}
        <svg className="logo" viewBox="0 0 32 32" width="19" height="19" aria-hidden="true" focusable="false">
          <rect width="32" height="32" rx="7.5" fill="#0F766E" />
          <g fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round">
            <path d="M10.6 16C15 16 15.4 9.6 20.4 9.6" />
            <path d="M10.6 16C15 16 15.4 22.4 20.4 22.4" />
          </g>
          <g fill="#fff">
            <circle cx="8.6" cy="16" r="3" />
            <circle cx="22.6" cy="9.6" r="3" />
            <circle cx="22.6" cy="22.4" r="3" />
          </g>
        </svg>
        covenants.diy
      </div>
      <nav className="acts" role="menubar">
        {(["file", "edit", "view"] as const).map((which) => (
          <button
            key={which}
            ref={refs[which]}
            role="menuitem"
            aria-haspopup="menu"
            aria-expanded={open === which}
            className={`act ${open === which ? "on" : ""}`}
            // A menu bar opens on press, and once one is open, moving onto
            // the other opens that one, the way every menu bar behaves.
            onMouseDown={(e) => {
              e.preventDefault();
              openMenu(which, refs[which].current!);
            }}
            onMouseEnter={() => {
              if (open && open !== which) openMenu(which, refs[which].current!);
            }}
          >
            {which}
          </button>
        ))}
      </nav>
      <div className="sp" />
      <label className="sel">
        <span>network</span>
        <select value={network} onChange={(e) => setNetwork(e.target.value as (typeof NETWORKS)[number])}>
          {NETWORKS.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </label>
      <label className="sel">
        <span>assume active</span>
        <select value={ruleset} onChange={(e) => setRuleset(e.target.value)}>
          {Object.entries(RULESETS).map(([k, v]) => (
            <option key={k} value={k} title={v.hint}>
              {v.label}
            </option>
          ))}
        </select>
      </label>
      <a
        className="gh"
        href="https://github.com/askii21m/covenants-diy"
        target="_blank"
        rel="noreferrer noopener"
        title="Source on GitHub"
        aria-label="Source on GitHub"
      >
        <svg viewBox="0 0 16 16" width="20" height="20" aria-hidden="true" focusable="false">
          <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
        </svg>
      </a>
    </header>
  );
}

/** One tab per open document. Click switches, double-click renames in
 *  place, the × or a middle-click closes, + opens the new menu. */
function Tabs({ openMenu }: { openMenu: OpenMenu }) {
  const docs = useStore((s) => s.docs);
  const active = useStore((s) => s.active);
  const switchDoc = useStore((s) => s.switchDoc);
  const closeDoc = useStore((s) => s.closeDoc);
  const renameDoc = useStore((s) => s.renameDoc);
  const [editing, setEditing] = useState<string | null>(null);
  const add = useRef<HTMLButtonElement>(null);
  const strip = useRef<HTMLDivElement>(null);
  // The strip reflows as a tab closes, so the second click of a
  // double-click lands on the close button that slid under the cursor. A
  // close within the double-click window of the previous one is ignored.
  const lastClose = useRef(0);
  // The active tab is kept in view; the strip scrolls and hides its bar.
  useEffect(() => {
    strip.current?.querySelector(".tab.on")?.scrollIntoView({ inline: "nearest", block: "nearest" });
  }, [active, docs.length]);
  return (
    <div className="tabs" role="tablist">
      <div className="tab-scroll" ref={strip}>
        {docs.map((d) => (
          <div
            key={d.id}
            role="tab"
            aria-selected={d.id === active}
            className={`tab ${d.id === active ? "on" : ""}`}
            onClick={() => switchDoc(d.id)}
            onMouseDown={(e) => {
              if (e.button === 1) {
                e.preventDefault();
                closeDoc(d.id);
              }
            }}
          >
            <InlineName
              className="tab-name"
              value={d.name}
              placeholder="untitled"
              editing={editing === d.id}
              onStart={() => setEditing(d.id)}
              onCommit={(v) => {
                if (v) renameDoc(d.id, v);
                setEditing(null);
              }}
            />
            <button
              className="tab-x"
              aria-label={`close ${d.name}`}
              title="close"
              onClick={(e) => {
                e.stopPropagation();
                // The second click of a double-click lands on whatever slid
                // under the cursor, which is another document's close button.
                const now = Date.now();
                if (now - lastClose.current < 400) return;
                lastClose.current = now;
                closeDoc(d.id);
              }}
            >
              ×
            </button>
          </div>
        ))}
      </div>
      <button
        ref={add}
        className="tab-add"
        aria-label="new document"
        title="new"
        onMouseDown={(e) => {
          e.preventDefault();
          openMenu("new", add.current!);
        }}
      >
        +
      </button>
    </div>
  );
}

/** Autosave was refused, so the work is only in memory. In the layout,
 *  above the tabs, so it covers nothing. */
function SaveBanner() {
  const [hidden, setHidden] = useState(false);
  if (hidden) return null;
  return (
    <div className="banner" role="alert">
      <span>
        Autosave failed: the browser refused the write, most likely because storage is full. Your work is only in this
        tab. Export what you want to keep, or close documents you no longer need.
      </span>
      <button className="banner-x" aria-label="dismiss" title="dismiss" onClick={() => setHidden(true)}>
        ×
      </button>
    </div>
  );
}

function Divider() {
  const setPanelHeight = useStore((s) => s.setPanelHeight);
  const dragging = useRef(false);
  return (
    <div
      className="div"
      role="separator"
      aria-orientation="horizontal"
      title="drag to resize"
      onPointerDown={(e) => {
        dragging.current = true;
        (e.target as HTMLElement).setPointerCapture(e.pointerId);
      }}
      onPointerMove={(e) => {
        if (dragging.current) setPanelHeight(window.innerHeight - e.clientY);
      }}
      onPointerUp={() => {
        dragging.current = false;
      }}
    />
  );
}

// Opening a link is asynchronous, so the store cannot be the latch:
// StrictMode invokes the effect twice and both passes see an empty
// document list before either has finished decoding.
let booted = false;

/** First load: a link if the URL carries one, otherwise the saved session,
 *  otherwise the vault example. ?fresh=1 ignores the session. */
function Boot({ openExample, say }: { openExample: (key: string) => void; say: (t: string) => void }) {
  const restore = useStore((s) => s.restoreSession);
  const newDoc = useStore((s) => s.newDoc);

  /** Open a shared graph and take it off the URL, so a reload does not
   *  reopen it on top of whatever has been done since. */
  const openShared = useCallback(
    async (shared: SharedDoc | null) => {
      history.replaceState(null, "", "/");
      if (shared) newDoc(shared.name || "shared", shared.flow);
      else say("That link does not carry a graph.");
      return Boolean(shared);
    },
    [newDoc, say],
  );

  useEffect(() => {
    // Idempotent: StrictMode runs effects twice in development.
    if (booted || useStore.getState().docs.length) return;
    booted = true;
    // A link wins over everything: it is what the visitor asked for. A
    // short one names a stored graph, a long one carries the graph itself.
    const id = idOnUrl();
    if (id) {
      void fetchShared(id)
        .then(openShared)
        .then((ok) => {
          if (!ok) openExample("vault");
        });
      return;
    }
    const fragment = fragmentOnUrl();
    if (fragment) {
      void decodeFlow(fragment)
        .then(openShared)
        .then((ok) => {
          if (!ok) openExample("vault");
        });
      return;
    }
    // ?fresh=1 ignores the session, and the autosave is about to replace
    // it, so keep a copy: it is the escape hatch for a session that breaks
    // the app, not a way to destroy it.
    const fresh = new URLSearchParams(location.search).get("fresh");
    if (fresh) backup(rawSession());
    const sess = fresh ? null : savedSession();
    if (sess?.docs.length) restore(sess);
    else openExample("vault");
  }, [restore, openExample, openShared]);

  // A link pasted into the address bar of a tab that is already open only
  // changes the fragment: the page is never reloaded, so nothing above
  // runs again. Without this, such a link would silently do nothing.
  useEffect(() => {
    const onHash = () => {
      const f = fragmentOnUrl();
      if (f) void decodeFlow(f).then(openShared);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [openShared]);

  return null;
}

export default function App() {
  const panelHeight = useStore((s) => s.panelHeight);
  const hasClosed = useStore((s) => s.closed.length > 0);
  const canUndo = useStore((s) => s.past.length > 0);
  const canRedo = useStore((s) => s.future.length > 0);
  const hasClipboard = useStore((s) => s.clipboard != null);
  const hasSelection = useStore((s) => s.nodes.some((n) => n.selected));
  const saveError = useStore((s) => s.saveError);
  const reopenClosed = useStore((s) => s.reopenClosed);
  const showMinimap = useStore((s) => s.showMinimap);
  const toggleMinimap = useStore((s) => s.toggleMinimap);
  const { openBlank, openExample, openFile } = useOpeners();
  const [menu, setMenu] = useState<{ which: MenuName; x: number; y: number; trigger: HTMLElement } | null>(null);
  // Counted, not boolean, so the same message twice re-announces and
  // resets the timer.
  const [toast, setToast] = useState<{ n: number; text: string } | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const say = useCallback((text: string) => {
    setToast((t) => ({ n: (t?.n ?? 0) + 1, text }));
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 3000);
  }, []);
  const file = useRef<HTMLInputElement>(null);
  const openMenu = useCallback<OpenMenu>((which, trigger) => {
    const r = trigger.getBoundingClientRect();
    setMenu((m) =>
      m && m.which === which && m.trigger === trigger ? null : { which, x: r.left, y: r.bottom + 4, trigger },
    );
  }, []);
  const copyLink = useCallback(() => {
    const s = useStore.getState();
    const name = s.docs.find((d) => d.id === s.active)?.name;
    // The write has to happen inside the click that asked for it. Awaiting
    // the upload first lets the user activation lapse, and the clipboard
    // then refuses with NotAllowedError, which is what every "could not
    // copy the link" was. Handing the clipboard the promise instead keeps
    // the write inside the gesture.
    const url = shortLink({ name, flow: { nodes: s.nodes, edges: s.edges, network: s.network, ruleset: s.ruleset } });
    const written =
      typeof ClipboardItem === "function" && navigator.clipboard?.write
        ? navigator.clipboard.write([
            new ClipboardItem({ "text/plain": url.then((u) => new Blob([u], { type: "text/plain" })) }),
          ])
        : url.then((u) => navigator.clipboard.writeText(u));
    void written.then(
      () => say("Link copied to clipboard."),
      // A refusal can arrive before the upload has even finished, so ask the
      // upload how it went rather than blaming whichever failed first.
      async () =>
        say(
          await url.then(
            () => "Could not write to the clipboard.",
            () => "Could not reach the server, so there is no link.",
          ),
        ),
    );
  }, [say]);

  // Everything that opens a document, shared by File > New and the + on
  // the tab strip, which are the same act from two places.
  const newItems: MenuItem[] = [
    { label: "Empty canvas", onClick: openBlank },
    // Examples grouped by what has to be deployed for them to mean
    // anything, rather than one flat list of eight.
    ...EXAMPLE_GROUPS.flatMap(({ title, keys }) => [
      { separator: true, label: "" },
      { label: title, heading: true },
      ...keys.map((k) => ({
        label: EXAMPLES[k].label,
        detail: EXAMPLES[k].blurb,
        shortcut: EXAMPLES[k].needs,
        onClick: () => openExample(k),
      })),
    ]),
  ];

  const fileItems: MenuItem[] = [
    { label: "New", submenu: newItems },
    { label: "Reopen closed tab", onClick: reopenClosed, disabled: !hasClosed },
    { separator: true, label: "" },
    { label: "Import\u2026", onClick: () => file.current?.click() },
    {
      label: "Export",
      submenu: [
        { label: "Flow file\u2026", detail: "a .covenants.json this editor can open again", onClick: exportJson },
        { label: "Permalink", detail: "stores the graph and copies a short link to it", onClick: copyLink },
      ],
    },
  ];

  const viewItems: MenuItem[] = [
    { label: "Zoom in", onClick: () => viewActions.zoomIn() },
    { label: "Zoom out", onClick: () => viewActions.zoomOut() },
    { label: "Actual size", onClick: () => viewActions.reset() },
    { separator: true, label: "" },
    { label: "Frame all", shortcut: "Home", onClick: () => viewActions.frameAll() },
    { label: "Frame selection", shortcut: "F", onClick: () => viewActions.frameSelection(), disabled: !hasSelection },
    { separator: true, label: "" },
    { label: "Minimap", checked: showMinimap, onClick: toggleMinimap },
  ];

  const editItems: MenuItem[] = [
    { label: "Undo", shortcut: "⌘Z", onClick: () => useStore.getState().undo(), disabled: !canUndo },
    { label: "Redo", shortcut: "⇧⌘Z", onClick: () => useStore.getState().redo(), disabled: !canRedo },
    { separator: true, label: "" },
    { label: "Copy", shortcut: "⌘C", onClick: () => useStore.getState().copy(), disabled: !hasSelection },
    { label: "Paste", shortcut: "⌘V", onClick: () => useStore.getState().paste(), disabled: !hasClipboard },
    { label: "Duplicate", shortcut: "⌘D", onClick: () => useStore.getState().duplicate(), disabled: !hasSelection },
    { label: "Delete", shortcut: "⌫", onClick: () => useStore.getState().removeSelected(), disabled: !hasSelection },
    { separator: true, label: "" },
    { label: "Select all", shortcut: "⌘A", onClick: () => useStore.getState().selectAll() },
    {
      label: "Comment around selection",
      shortcut: "C",
      onClick: () => useStore.getState().commentAroundSelection(),
      disabled: !hasSelection,
    },
  ];

  return (
    <ReactFlowProvider>
      <div className="app" style={{ ["--panel" as string]: `${panelHeight}px` }}>
        <TopBar openMenu={openMenu} open={menu?.which ?? null} />
        <Library />
        <main className="cv">
          {saveError && <SaveBanner />}
          <Tabs openMenu={openMenu} />
          <Canvas />
          <Boot openExample={openExample} say={say} />
        </main>
        <Divider />
        <section className="panel">
          <Detail />
        </section>
        {menu && (
          <ContextMenu
            x={menu.x}
            y={menu.y}
            items={
              menu.which === "file"
                ? fileItems
                : menu.which === "edit"
                  ? editItems
                  : menu.which === "view"
                    ? viewItems
                    : newItems
            }
            ignore={menu.trigger}
            onClose={() => setMenu(null)}
          />
        )}
        <input
          ref={file}
          type="file"
          accept="application/json,.json"
          hidden
          onChange={async (e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            const ok = await openFile(f);
            if (ok === false) say("That file is not a covenants flow.");
          }}
        />
        {toast && (
          <div className="toast" role="alert" key={toast.n}>
            {toast.text}
          </div>
        )}
      </div>
    </ReactFlowProvider>
  );
}
