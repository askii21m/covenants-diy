import { type Env, MAX_PAYLOAD, idFor, json, summarise } from "../_shared";

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const payload = await request.text();
  if (!payload || payload.length > MAX_PAYLOAD) return json({ error: "too large" }, 413);

  const summary = await summarise(payload);
  if (!summary) return json({ error: "not a graph" }, 400);

  // Ten characters of hash is sixty bits. Two different graphs landing on
  // the same ten is remote but not impossible, so the id grows until it
  // names one graph.
  const full = await idFor(payload);
  let id = "";
  for (let len = 10; len <= 20; len += 2) {
    id = full.slice(0, len);
    const row = await env.GRAPHS.prepare("SELECT payload FROM graphs WHERE id = ?").bind(id).first<{ payload: string }>();
    if (!row) break;
    if (row.payload === payload) return json({ id });
    id = "";
  }
  if (!id) return json({ error: "could not place it" }, 500);

  await env.GRAPHS.prepare(
    `INSERT INTO graphs (id, payload, bytes, nodes, edges, network, ruleset, kinds, created, views)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
     ON CONFLICT(id) DO NOTHING`,
  ).bind(id, payload, payload.length, summary.nodes, summary.edges, summary.network, summary.ruleset, summary.kinds, Date.now()).run();

  return json({ id });
};

export const onRequest: PagesFunction<Env> = async () => json({ error: "post a graph" }, 405);
