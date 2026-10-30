#!/usr/bin/env node
/**
 * Measures the kinematic judge on a LABELED corpus and reports error rates with 95% Wilson intervals, per cohort.
 *
 *   node scripts/eval-kinematics.mjs corpus.jsonl [--max-fpr 0.02] [--min-humans 400] [--json]
 *
 * Each JSONL line: {"label":"human"|"bot","cohort":"mouse|touch|assistive|...","evidence":<KinematicEvidence>}
 * A human counts as a false positive when the verdict is anything other than "ok" (they would be escalated).
 * The synthetic generator in the test-suite is NOT a representative corpus; this tool exists so real, consented,
 * representative captures (including assistive-technology users) can be measured. See docs/EVALUATION.md.
 */
import { readFileSync } from 'node:fs';
import { judgeKinematics } from '@biokyn/protocol';
import { requiredSamples, wilson } from './lib/stats.mjs';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
const opt = (name, dflt) => { const i = args.indexOf(`--${name}`); return i >= 0 ? Number(args[i + 1]) : dflt; };
if (!file) { console.error('usage: eval-kinematics.mjs corpus.jsonl [--max-fpr 0.02] [--min-humans 400] [--json]'); process.exit(2); }
const maxFpr = opt('max-fpr', 0.02), minHumans = opt('min-humans', 400);

const cohorts = new Map();
const cell = (c) => { if (!cohorts.has(c)) cohorts.set(c, { human: { n: 0, flagged: 0 }, bot: { n: 0, caught: 0 } }); return cohorts.get(c); };
for (const [i, line] of readFileSync(file, 'utf8').split('\n').entries()) {
  if (!line.trim()) continue;
  let row; try { row = JSON.parse(line); } catch { throw new Error(`line ${i + 1}: invalid JSON`); }
  if (!['human', 'bot'].includes(row.label) || !row.evidence) throw new Error(`line ${i + 1}: needs label and evidence`);
  const verdict = judgeKinematics(row.evidence).verdict;
  for (const c of [row.cohort ?? 'all', 'ALL']) {
    const x = cell(c);
    if (row.label === 'human') { x.human.n++; if (verdict !== 'ok') x.human.flagged++; }
    else { x.bot.n++; if (verdict !== 'ok') x.bot.caught++; }
  }
}
const pct = (v) => `${(v * 100).toFixed(2)}%`;
let failed = false; const out = [];
for (const [name, x] of [...cohorts].sort()) {
  const fp = wilson(x.human.flagged, x.human.n), tp = wilson(x.bot.caught, x.bot.n);
  const enough = x.human.n >= minHumans;
  const gateOk = enough && fp.hi <= maxFpr;
  if (name === 'ALL' || x.human.n > 0) if (!gateOk) failed = true;
  out.push({ cohort: name, humans: x.human.n, falsePositives: x.human.flagged, fpr: fp.p, fprCI95: [fp.lo, fp.hi], bots: x.bot.n, caught: x.bot.caught, tpr: tp.p, tprCI95: [tp.lo, tp.hi], enoughHumans: enough, meetsFprGate: gateOk });
}
if (args.includes('--json')) console.log(JSON.stringify(out, null, 2));
else {
  console.log(`FPR gate: upper 95% bound <= ${pct(maxFpr)} with >= ${minHumans} humans per cohort (n for ±2pp at p=2%: ${requiredSamples(0.02, 0.02)})\n`);
  for (const r of out) console.log(`${r.cohort.padEnd(14)} humans=${String(r.humans).padStart(6)} FP=${pct(r.fpr)} [${pct(r.fprCI95[0])}, ${pct(r.fprCI95[1])}]  bots=${String(r.bots).padStart(6)} caught=${pct(r.tpr)} [${pct(r.tprCI95[0])}, ${pct(r.tprCI95[1])}]  ${r.meetsFprGate ? 'PASS' : r.enoughHumans ? 'FAIL (FPR too high or uncertain)' : 'INSUFFICIENT SAMPLE'}`);
}
process.exit(failed ? 1 : 0);
