// The add-node search menu and the context menus. All of them open at a
// screen position, close on Escape or an outside click, and are driven by
// the keyboard.

import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ComponentProps } from "react";
import { CATEGORIES, KINDS, firstCompatibleInput, firstCompatibleOutput, type Port } from "../registry";

export interface MenuItem {
  label: string;
  shortcut?: string;
  onClick?: () => void;
  disabled?: boolean;
  separator?: boolean;
  heading?: boolean;
  detail?: string;
  /** Rows shown in a panel to the right. An item with one has no action of
   *  its own: opening the panel is the action. */
  submenu?: MenuItem[];
  /** Drawn with a tick, for the things View turns on and off. */
  checked?: boolean;
  /** Stay open after a pick, for a row of switches you set several of. */
  keepOpen?: boolean;
}

/** The gap between a panel and its submenu, and the padding inside a panel,
 *  which is what the first submenu row has to be lifted by to sit level
 *  with the row that opened it. Both match app.css. */
const GAP = 4;
const PAD = 6;

const live = (items: MenuItem[]) =>
  items.map((it, i) => ({ it, i })).filter(({ it }) => !it.separator && !it.heading && !it.disabled);

function Row({ it, className, ...rest }: { it: MenuItem; className: string } & ComponentProps<"button">) {
  return (
    <button
      className={className}
      role="menuitem"
      disabled={it.disabled}
      tabIndex={-1}
      title={it.label}
      aria-haspopup={it.submenu ? "menu" : undefined}
      {...rest}
    >
      {it.checked !== undefined && (
        <i className="menu-tick" aria-hidden="true">
          {it.checked ? "✓" : ""}
        </i>
      )}
      <span>{it.label}</span>
      {it.shortcut && <kbd>{it.shortcut}</kbd>}
      {it.detail && <em>{it.detail}</em>}
      {it.submenu && (
        <i className="menu-more" aria-hidden="true">
          ›
        </i>
      )}
    </button>
  );
}

export function ContextMenu({
  x,
  y,
  items,
  onClose,
  ignore,
  className,
}: {
  x: number;
  y: number;
  items: MenuItem[];
  onClose: () => void;
  /** Extra class on the panel, for a menu whose rows need more room. */
  className?: string;
  /** The element that opened the menu: a press on it does not count as
   *  outside, so the trigger can toggle the menu closed. */
  ignore?: HTMLElement | null;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const uid = useId();
  /** The panel element and its rows, per level, level 0 being the root. */
  const panels = useRef<(HTMLDivElement | null)[]>([]);
  const rows = useRef<(HTMLButtonElement | null)[][]>([]);
  // State lives in refs as well as in state, so two keys in one tick
  // (ArrowDown then Enter) see each other.
  /** One entry per open submenu, outermost first: the row that opened it and
   *  where its panel sits. Panel `d + 1` is described by `open[d]`. */
  type Sub = { at: number; x: number; y: number };
  const [open, setOpenState] = useState<Sub[]>([]);
  const openRef = useRef<Sub[]>([]);
  const setOpen = (v: Sub[]) => {
    openRef.current = v;
    setOpenState(v);
  };
  /** The cursor in each panel, so the arrows resume where they left off. */
  const [cursors, setCursorsState] = useState<number[]>([-1]);
  const cursorsRef = useRef<number[]>([-1]);
  const setCursors = (v: number[]) => {
    cursorsRef.current = v;
    setCursorsState(v);
  };

  /** What each panel shows, walked down from the root. A submenu that is no
   *  longer there ends the walk rather than leaving a panel with no items. */
  const lists = useMemo(() => {
    const out: MenuItem[][] = [items];
    for (const lv of open) {
      const next = out[out.length - 1][lv.at]?.submenu;
      if (!next) break;
      out.push(next);
    }
    return out;
  }, [items, open]);

  /** Open the submenu of row `at` in panel `d`, closing anything deeper. */
  const openSub = (d: number, at: number) => {
    const box = panels.current[d]?.getBoundingClientRect();
    const row = rows.current[d]?.[at]?.getBoundingClientRect();
    const list = listsNow()[d]?.[at]?.submenu;
    if (!box || !row || !list) return;
    // Off the panel's outer edge, not the row's: a row is inset by the
    // panel's padding, so hanging the submenu from it puts the submenu on
    // top of the parent's border. Its first item lines up with the row that
    // opened it, and it flips to the left when there is no room on the right.
    const w = 300,
      h = Math.min(list.length * 30 + 12, window.innerHeight - 16);
    const x = box.right + GAP + w > window.innerWidth - 8 ? Math.max(8, box.left - GAP - w) : box.right + GAP;
    const y = Math.max(8, Math.min(row.top - PAD, window.innerHeight - 8 - h));
    setOpen([...openRef.current.slice(0, d), { at, x, y }]);
    setCursors([...cursorsRef.current.slice(0, d + 1), -1]);
  };

  /** Close every panel deeper than `d`. */
  const closeBelow = (d: number) => {
    setOpen(openRef.current.slice(0, d));
    setCursors(cursorsRef.current.slice(0, d + 1));
  };

  /** The panels as they stand this instant, walked from the ref rather than
   *  from state, so two keys in one tick (ArrowRight then ArrowDown) see
   *  each other instead of the second one landing on the panel the first
   *  just left. */
  const listsNow = () => {
    const out: MenuItem[][] = [state.current.items];
    for (const lv of openRef.current) {
      const next = out[out.length - 1][lv.at]?.submenu;
      if (!next) break;
      out.push(next);
    }
    return out;
  };

  const state = useRef({ items, onClose, openSub, closeBelow, listsNow });
  state.current = { items, onClose, openSub, closeBelow, listsNow };

  // A menu takes focus while it is open and gives it back on close, so a
  // field keeps its own keys when it has them and the menu has them
  // otherwise: Escape closes, arrows move, Enter or Space picks, Tab stays
  // inside. Other keys go nowhere, but their defaults (browser shortcuts)
  // are left alone.
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null;
    ref.current?.focus({ preventScroll: true });
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (ref.current?.contains(t) || ignore?.contains(t)) return;
      state.current.onClose();
    };
    const step = (list: { i: number }[], at: number, key: string) =>
      at < 0
        ? key === "ArrowDown"
          ? 0
          : list.length - 1
        : key === "ArrowDown"
          ? (at + 1) % list.length
          : (at - 1 + list.length) % list.length;
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
      const { onClose, openSub, closeBelow, listsNow } = state.current;
      const lists = listsNow();
      // Browser shortcuts stay the browser's: swallowing \u2318D without
      // preventing it opened the bookmark dialog with a menu on screen.
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      e.stopImmediatePropagation();
      // The deepest open panel takes the keys, and Escape or ArrowLeft hands
      // them back one level at a time rather than closing the lot.
      const d = lists.length - 1;
      const here = live(lists[d]);
      const at = cursorsRef.current[d] ?? -1;
      const hit = here.find(({ i }) => i === at);
      if (e.key === "Escape") {
        e.preventDefault();
        if (d > 0) closeBelow(d - 1);
        else onClose();
        return;
      }
      // Tab leaves the menu, as the ARIA menu pattern expects.
      if (e.key === "Tab") {
        onClose();
        return;
      }
      if (e.key === "ArrowLeft") {
        if (d > 0) {
          e.preventDefault();
          closeBelow(d - 1);
        }
        return;
      }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        if (!here.length) return;
        const next =
          here[
            step(
              here,
              here.findIndex(({ i }) => i === at),
              e.key,
            )
          ].i;
        setCursors([...cursorsRef.current.slice(0, d), next]);
        return;
      }
      if (e.key === "ArrowRight") {
        if (hit?.it.submenu) {
          e.preventDefault();
          openSub(d, hit.i);
        }
        return;
      }
      if (e.key === "Enter" || e.key === " ") {
        if (!hit) return;
        e.preventDefault();
        if (hit.it.submenu) {
          openSub(d, hit.i);
          return;
        }
        hit.it.onClick?.();
        if (!hit.it.keepOpen) onClose();
      }
    };
    window.addEventListener("mousedown", onDown, true);
    window.addEventListener("keydown", onKey, true);
    return () => {
      window.removeEventListener("mousedown", onDown, true);
      window.removeEventListener("keydown", onKey, true);
      if (before && before.isConnected && document.activeElement === document.body)
        before.focus({ preventScroll: true });
    };
  }, [ignore]);
  // A hovered item that went disabled must not stay the cursor.
  useEffect(() => {
    const at = cursorsRef.current[0] ?? -1;
    if (at >= 0 && !live(items).some(({ i }) => i === at)) setCursors([-1]);
  }, [items]);
  // Clamped against the estimate first, then against the box once it has
  // one: 220 and 340 wide are both common, and separators and headings are
  // not 30px tall.
  const [pos, setPos] = useState(() =>
    clampToViewport(x, y, 240, Math.min(items.length * 30 + 12, window.innerHeight - 16)),
  );
  useLayoutEffect(() => {
    const r = ref.current?.getBoundingClientRect();
    if (r) setPos(clampToViewport(x, y, r.width, r.height));
  }, [x, y, items.length]);

  const panelRows = (d: number, list: MenuItem[]) =>
    list.map((it, i) =>
      it.separator ? (
        <div className="menu-sep" key={i} />
      ) : it.heading ? (
        <div className="menu-cat" key={i}>
          {it.label}
        </div>
      ) : (
        <Row
          key={i}
          it={it}
          id={d === 0 ? `${uid}-${i}` : undefined}
          className={`menu-item ${i === (cursors[d] ?? -1) ? "cur" : ""}`}
          ref={(el: HTMLButtonElement | null) => {
            (rows.current[d] ??= [])[i] = el;
          }}
          aria-expanded={it.submenu ? open[d]?.at === i : undefined}
          onMouseEnter={() => {
            setCursors([...cursorsRef.current.slice(0, d), i]);
            if (it.submenu) openSub(d, i);
            else closeBelow(d);
          }}
          onClick={() => {
            if (it.submenu) {
              openSub(d, i);
              return;
            }
            it.onClick?.();
            if (!it.keepOpen) onClose();
          }}
        />
      ),
    );

  return (
    <div
      className={`menu ${className ?? ""}`}
      ref={(el) => {
        ref.current = el;
        panels.current[0] = el;
      }}
      style={{ left: pos.x, top: pos.y }}
      role="menu"
      tabIndex={-1}
      aria-activedescendant={(cursors[0] ?? -1) >= 0 ? `${uid}-${cursors[0]}` : undefined}
    >
      {panelRows(0, items)}
      {/* Inside the parent box in the DOM, so a press in here is not an
          outside click and does not close the menu it belongs to. */}
      {open.map((lv, k) =>
        lists[k + 1] ? (
          <div
            className="menu menu-sub"
            role="menu"
            key={k}
            style={{ left: lv.x, top: lv.y }}
            ref={(el) => {
              panels.current[k + 1] = el;
            }}
          >
            {panelRows(k + 1, lists[k + 1])}
          </div>
        ) : null,
      )}
    </div>
  );
}

export interface AddMenuProps {
  x: number;
  y: number;
  /** Only kinds with a port this one can reach are offered, and the menu
   *  says which pin will be wired. */
  pendingPort?: Port;
  pendingSide?: "source" | "target";
  onPick: (kind: string) => void;
  onClose: () => void;
}

export function AddMenu({ x, y, pendingPort, pendingSide, onPick, onClose }: AddMenuProps) {
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    input.current?.focus();
  }, []);
  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (!box.current?.contains(e.target as Node)) onClose();
    };
    window.addEventListener("mousedown", onDown, true);
    return () => window.removeEventListener("mousedown", onDown, true);
  }, [onClose]);

  const items = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return Object.values(KINDS)
      .filter((k) => k.kind !== "reroute")
      .filter(
        (k) =>
          !needle ||
          k.label.toLowerCase().includes(needle) ||
          k.description.toLowerCase().includes(needle) ||
          k.category.toLowerCase().includes(needle),
      )
      .map((k) => {
        const d = k.defaults();
        const pin =
          pendingPort == null
            ? undefined
            : pendingSide === "source"
              ? firstCompatibleInput({ ...d, kind: k.kind }, pendingPort)
              : firstCompatibleOutput({ ...d, kind: k.kind }, pendingPort);
        return { kind: k, pin, ok: pendingPort == null || !!pin };
      })
      .sort(
        (a, b) =>
          Number(b.ok) - Number(a.ok) || CATEGORIES.indexOf(a.kind.category) - CATEGORIES.indexOf(b.kind.category),
      );
  }, [q, pendingPort, pendingSide]);

  useEffect(() => {
    setCursor(0);
  }, [q]);
  const pos = clampToViewport(x, y, 300, 380);

  return (
    // A press on the menu's own chrome (a heading, the list, the scrollbar)
    // must not blur the search box: the canvas keyboard would take over and
    // Delete would remove the node behind the menu.
    <div
      className="menu add"
      ref={box}
      style={{ left: pos.x, top: pos.y }}
      onMouseDown={(e) => {
        if (!(e.target instanceof HTMLElement) || !e.target.closest("input,button")) e.preventDefault();
      }}
    >
      <input
        ref={input}
        className="menu-search"
        placeholder={pendingPort ? `Add a node to connect ${pendingPort.type}…` : "Add node…"}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setCursor((c) => Math.min(items.length - 1, c + 1));
          }
          if (e.key === "ArrowUp") {
            e.preventDefault();
            setCursor((c) => Math.max(0, c - 1));
          }
          if (e.key === "Enter" && items[cursor]?.ok) {
            e.preventDefault();
            onPick(items[cursor].kind.kind);
          }
          if (e.key === "Escape") onClose();
        }}
      />
      <div className="menu-list">
        {CATEGORIES.map((cat) => {
          const group = items.filter((it) => it.kind.category === cat);
          if (!group.length) return null;
          return (
            <div key={cat}>
              <div className="menu-cat">{cat}</div>
              {group.map((it) => {
                const idx = items.indexOf(it);
                return (
                  <button
                    key={it.kind.kind}
                    className={`menu-item ${idx === cursor ? "cur" : ""} ${it.ok ? "" : "off"}`}
                    disabled={!it.ok}
                    onMouseEnter={() => setCursor(idx)}
                    onClick={() => it.ok && onPick(it.kind.kind)}
                  >
                    <span>{it.kind.label}</span>
                    {it.pin && <kbd>→ {it.pin.label || "in"}</kbd>}
                  </button>
                );
              })}
            </div>
          );
        })}
        {!items.length && <div className="menu-empty">Nothing matches.</div>}
      </div>
    </div>
  );
}

function clampToViewport(x: number, y: number, w: number, h: number) {
  return {
    x: Math.max(8, Math.min(x, window.innerWidth - w - 8)),
    y: Math.max(8, Math.min(y, window.innerHeight - h - 8)),
  };
}
