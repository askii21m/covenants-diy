// Syntax colouring for tapscript source. Shared by the inline view on a
// node and the editor in the panel, so they never disagree.
import type { ReactNode } from "react";

export interface SourceError { line: number; word: number; message: string }

export function highlight(source: string, err?: SourceError, bound?: Record<string, string>): ReactNode[] {
  const out: ReactNode[] = [];
  source.split("\n").forEach((line, li) => {
    if (li > 0) out.push("\n");
    const hashAt = line.indexOf("#");
    const code = hashAt >= 0 ? line.slice(0, hashAt) : line;
    const comment = hashAt >= 0 ? line.slice(hashAt) : "";
    let wi = 0;
    const re = /(\S+)|(\s+)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(code))) {
      if (m[2]) { out.push(m[2]); continue; }
      const word = m[1];
      const bad = err && err.line === li && err.word === wi;
      let cls = word.startsWith("@") ? "ref" : /^(OP_)?[A-Z][A-Z0-9_]+$/.test(word) ? "op" : /^-?\d+$|^<[0-9a-fA-F]*>$|^(0x)?[0-9a-fA-F]{2,}$/.test(word) ? "num" : "";
      if (word.startsWith("@") && bound && !bound[word.slice(1)]) cls += " unbound";
      if (bad) cls += " bad";
      const title = bad ? err!.message : word.startsWith("@") ? (bound?.[word.slice(1)] ? `${word} = ${bound[word.slice(1)]}` : `${word}: nothing wired`) : undefined;
      out.push(<span key={`${li}-${wi}`} className={cls.trim() || undefined} title={title}>{word}</span>);
      wi++;
    }
    if (comment) out.push(<span key={`c${li}`} className="cm">{comment}</span>);
  });
  return out;
}
