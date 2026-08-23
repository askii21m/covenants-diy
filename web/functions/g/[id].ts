import { type Env } from "../_shared";

/** A shared graph is opened by the app, not by the server, so this path
 *  serves the same shell as the root and lets the client read the id.
 *  A _redirects rule cannot do it: Pages reads /g/* -> /index.html as a
 *  loop and drops the rule. */
export const onRequestGet: PagesFunction<Env> = ({ request, env }) => {
  const url = new URL(request.url);
  url.pathname = "/";
  return env.ASSETS.fetch(new Request(url.toString(), { headers: request.headers }));
};
