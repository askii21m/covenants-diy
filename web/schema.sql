-- Cloudflare D1. Create the database and apply this once:
--   wrangler d1 create covenants
--   wrangler d1 execute covenants --remote --file=web/schema.sql

CREATE TABLE IF NOT EXISTS graphs (
  id        TEXT PRIMARY KEY,
  payload   TEXT NOT NULL,
  bytes     INTEGER NOT NULL,
  nodes     INTEGER NOT NULL,
  edges     INTEGER NOT NULL,
  network   TEXT,
  ruleset   TEXT,
  kinds     TEXT,
  created   INTEGER NOT NULL,
  views     INTEGER NOT NULL DEFAULT 0,
  last_view INTEGER
);

CREATE INDEX IF NOT EXISTS graphs_created ON graphs (created);
CREATE INDEX IF NOT EXISTS graphs_views   ON graphs (views);
