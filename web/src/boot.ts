import { useStore, savedSession, backup, rawSession } from "./store";
import { decodeFlow, fetchShared, fragmentOnUrl, idOnUrl, type SharedDoc } from "./share";

/** Open a shared graph as a new tab and take it off the URL, so a reload
 *  does not reopen it on top of whatever has been done since. */
export function openShared(shared: SharedDoc | null, say: (t: string) => void): boolean {
  history.replaceState(null, "", "/");
  if (shared) useStore.getState().newDoc(shared.name || "shared", shared.flow);
  else say("That link does not carry a graph.");
  return Boolean(shared);
}

/** First load: the saved session comes back first, then a link, if the URL
 *  carries one, opens on top of it. With neither, the vault example.
 *  ?fresh=1 ignores the session.
 *
 *  The order matters. The autosave writes whatever is open, so a link that
 *  opened before the session was read would replace a visitor's own work
 *  with the graph someone sent them. */
export async function boot(openExample: (key: string) => void, say: (t: string) => void): Promise<void> {
  // The autosave is about to replace the ignored session, so keep a copy:
  // ?fresh=1 is the escape hatch for a session that breaks the app, not a
  // way to destroy it.
  const fresh = new URLSearchParams(location.search).get("fresh");
  if (fresh) backup(rawSession());
  const sess = fresh ? null : savedSession();
  if (sess?.docs.length) useStore.getState().restoreSession(sess);

  // A short link names a stored graph, a long one carries the graph itself.
  const id = idOnUrl();
  const fragment = id ? null : fragmentOnUrl();
  let opened = false;
  if (id) opened = openShared(await fetchShared(id), say);
  else if (fragment) opened = openShared(await decodeFlow(fragment), say);

  if (!opened && !useStore.getState().docs.length) openExample("vault");
}
