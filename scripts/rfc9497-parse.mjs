/**
 * Parses RFC 9497 Appendix A.1 (ristretto255-SHA512) test vectors out of the RFC plain-text document.
 * Tolerates: table-of-contents entries with the same heading, form feeds, page headers/footers inside the appendix,
 * RFC 8792 backslash folding, and long hex values wrapped onto following lines (also when the value starts on the next line).
 */
const MODES = [['OPRF', 0], ['VOPRF', 1], ['POPRF', 2]];
const FIELDS = new Set(['seed', 'KeyInfo', 'skSm', 'pkSm', 'Input', 'Info', 'Blind', 'BlindedElement', 'EvaluationElement', 'Proof', 'ProofRandomScalar', 'Output']);
const isToc = (l) => /\.{3,}/.test(l) || /\s\d{1,3}\s*$/.test(l);          // "A.1.  ristretto255-SHA512 .......... 56"
const isPageNoise = (l) => /^\s*$/.test(l) || /\[Page \d+\]/.test(l) || /^RFC \d+\s+.*\d{4}\s*$/.test(l) || /\f/.test(l);

export function parseRfc9497(text) {
  // RFC 8792 line folding: a trailing backslash joins the next line (leading whitespace removed). Drop form feeds.
  const lines = text.replace(/\r/g, '').replace(/\f/g, '\n').replace(/\\\n\s*/g, '').split('\n');
  const heading = (re) => lines.map((l, i) => [l.trim(), i]).filter(([l]) => re.test(l) && !isToc(l)).map(([, i]) => i);
  const starts = heading(/^A\.1\.\s+ristretto255-SHA512/i);
  if (starts.length === 0) throw new Error('Appendix A.1 heading (ristretto255-SHA512) not found outside the table of contents');
  // the body heading is the last one: the table of contents (which precedes the body) lists the same headings
  const start = starts[starts.length - 1];
  let end = lines.findIndex((l, i) => i > start && /^A\.2\.\s/.test(l.trim()) && !isToc(l.trim()));
  if (end < 0) end = lines.length;

  const sets = []; let set = null, vec = null, last = null;
  const flush = () => { if (set && vec && vec.Input !== undefined) set.vectors.push(vec); vec = null; };
  for (const raw of lines.slice(start, end)) {
    const line = raw.trim();
    const mode = MODES.find(([name]) => new RegExp(`^A\\.1\\.\\d\\.\\s+${name}\\b`, 'i').test(line));
    if (mode) { flush(); set = { mode: mode[1], vectors: [] }; sets.push(set); last = null; continue; }
    if (!set) continue;
    const m = /^([A-Za-z]+)\s*=\s*([0-9a-fA-F,\s]*)$/.exec(line);
    if (m && FIELDS.has(m[1] === 'Seed' ? 'seed' : m[1])) {
      const [, rawKey, val] = m; const key = rawKey === 'Seed' ? 'seed' : rawKey; const v = val.replace(/\s+/g, '').toLowerCase();
      if (key === 'Input') { flush(); vec = {}; }
      if (['seed', 'KeyInfo', 'skSm', 'pkSm'].includes(key)) { set[key] = v; last = [set, key]; }
      else if (vec) { vec[key] = v; last = [vec, key]; }
      continue;
    }
    if (isPageNoise(line)) continue;                                        // page breaks never end a wrapped value
    if (last && /^[0-9a-fA-F]+$/.test(line)) last[0][last[1]] += line.toLowerCase(); // wrapped hex continuation
  }
  flush();
  for (const s of sets) {
    s.vectors = s.vectors.filter((v) => !/,/.test(v.Input ?? '')); // single-element vectors (batched vectors are verified separately)
    s.keyInfo = s.KeyInfo; delete s.KeyInfo;
  }
  const diag = sets.map((s) => `mode ${s.mode}: seed=${Boolean(s.seed)} keyInfo=${Boolean(s.keyInfo)} skSm=${Boolean(s.skSm)} vectors=${s.vectors.length}`).join('; ') || 'no sub-sections found';
  const ok = sets.filter((s) => s.seed && s.keyInfo && s.skSm && s.vectors.length > 0);
  if (!ok.some((s) => s.mode === 0) || !ok.some((s) => s.mode === 1)) throw new Error(`parsed vector sets incomplete (expected OPRF and VOPRF). Appendix body at line ${start}-${end}. Found: ${diag}`);
  for (const s of ok) for (const v of s.vectors) for (const f of ['Input', 'Blind', 'BlindedElement', 'EvaluationElement', 'Output']) if (v[f] === undefined) throw new Error(`mode ${s.mode} vector missing field ${f}. Found: ${diag}`);
  return ok.filter((s) => s.mode <= 1);
}
