import { type Env, ID_PATTERN, json } from "../../_shared";

export const onRequestGet: PagesFunction<Env, "id"> = async ({ params, env }) => {
  const id = String(params.id ?? "");
  if (!ID_PATTERN.test(id)) return json({ error: "not an id" }, 400);

  const row = await env.GRAPHS.prepare("SELECT payload FROM graphs WHERE id = ?").bind(id).first<{ payload: string }>();
  if (!row) return json({ error: "no such graph" }, 404);

  // Counted after the read, so a failure to count never costs a reader
  // their graph.
  await env.GRAPHS.prepare("UPDATE graphs SET views = views + 1, last_view = ? WHERE id = ?").bind(Date.now(), id).run();

  return new Response(row.payload, {
    headers: {
      "content-type": "text/plain; charset=utf-8",
      // A graph never changes under its id, so it can be cached hard.
      "cache-control": "public, max-age=31536000, immutable",
      // This is the one response made of bytes a stranger chose. Nothing
      // may be sniffed out of it, and navigating to it directly must not
      // give the result a document's privileges on this origin.
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; sandbox",
    },
  });
};
