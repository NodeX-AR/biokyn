/**
 * A minimal fake browser page that runs the REAL served script (LIVENESS_SCRIPT) in an isolated vm context that
 * exposes only `window` and `document`. If the script referenced anything else it would throw ReferenceError.
 */
import vm from 'node:vm';
import { LIVENESS_SCRIPT } from '../../client/src/live-script.js';
import { decodeReport, type LivenessReport } from '../src/liveness.js';

export function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32);
}

export interface Pt { x: number; y: number }
type Handler = (e: Record<string, unknown>) => void;

export function createPage(opts: { outerHeight?: number; seed?: number } = {}) {
  const clock = { t: 5000 };
  const rng = lcg(opts.seed ?? 1);
  const handlers = new Map<string, Handler[]>();
  const doc = {
    addEventListener(type: string, fn: Handler): void { handlers.set(type, [...(handlers.get(type) ?? []), fn]); },
    createElement: (): Record<string, unknown> => ({}),
  };
  const btn = { getBoundingClientRect: () => ({ left: 300, top: 200, width: 100, height: 40 }) };
  const field = {};
  const elsewhere = {};
  let hidden: { value?: string } | null = null;
  const form = {
    hasAttribute: (n: string) => n === 'data-biokyn',
    contains: (n: unknown) => n === btn || n === field || n === form,
    querySelector: () => hidden,
    appendChild: (c: { value?: string }) => { hidden = c; },
  };
  const win = {
    performance: { now: () => clock.t },
    crypto: { getRandomValues: (a: Uint8Array) => { for (let i = 0; i < a.length; i++) a[i] = Math.floor(rng() * 256); } },
    btoa: (s: string) => Buffer.from(s, 'binary').toString('base64'),
    innerHeight: 700,
    outerHeight: opts.outerHeight ?? 790,
  };
  vm.runInNewContext(LIVENESS_SCRIPT, { window: win, document: doc });

  const fire = (type: string, props: Record<string, unknown> = {}): void => {
    const e = { type, isTrusted: true, timeStamp: clock.t, clientX: 0, clientY: 0, screenX: 0, screenY: 0, target: btn, ...props };
    for (const h of handlers.get(type) ?? []) h(e);
  };
  const wait = (ms: number): void => { clock.t += ms; };
  const submit = (): string => { fire('submit', { target: form }); return hidden?.value ?? ''; };
  const report = (): LivenessReport => {
    const raw = submit();
    const r = decodeReport(raw);
    if (!r) throw new Error('report did not decode: ' + raw);
    return r;
  };
  return { clock, rng, fire, wait, submit, report, btn, field, elsewhere, form, win, rawLength: () => (hidden?.value ?? '').length };
}
export type Page = ReturnType<typeof createPage>;

const sc = (p: Pt) => ({ clientX: p.x, clientY: p.y, screenX: p.x + 100, screenY: p.y + 150 });

/** A person's approach: minimum-jerk position profile with lateral drift, timing and position jitter, then a pause. */
export function humanApproach(p: Page, from: Pt, to: Pt, o: { durationMs?: number; hz?: number } = {}): void {
  const T = o.durationMs ?? 520;
  const dt = 1000 / (o.hz ?? 125);
  const n = Math.round(T / dt);
  for (let i = 1; i <= n; i++) {
    const tau = i / n;
    const s = 10 * tau ** 3 - 15 * tau ** 4 + 6 * tau ** 5;
    const bump = 14 * Math.sin(Math.PI * tau);
    p.wait(dt + (p.rng() - 0.5) * 3);
    p.fire('pointermove', { ...sc({ x: from.x + (to.x - from.x) * s + (p.rng() - 0.5) * 1.2, y: from.y + (to.y - from.y) * s + bump + (p.rng() - 0.5) * 1.2 }), pointerType: 'mouse', getCoalescedEvents: () => [{}, {}] });
  }
  p.wait(90 + p.rng() * 60);
}

export function pressAt(p: Page, pt: Pt, o: { dwell?: number; pointerType?: string; detail?: number; target?: unknown } = {}): void {
  const extra = { pointerType: o.pointerType ?? 'mouse', button: 0, ...(o.target !== undefined ? { target: o.target } : {}) };
  p.fire('pointerdown', { ...sc(pt), ...extra });
  p.wait(o.dwell ?? 85);
  p.fire('pointerup', { ...sc({ x: pt.x + (p.rng() - 0.5) * 2, y: pt.y + (p.rng() - 0.5) * 2 }), ...extra });
  p.fire('click', { ...sc(pt), detail: o.detail ?? 1, ...(o.target !== undefined ? { target: o.target } : {}) });
}

/** Human: moves, hovers, presses ~(+6,-4) off-centre with a normal dwell. */
export function humanClick(p: Page, from: Pt = { x: 80, y: 500 }, dwell = 85): void {
  humanApproach(p, from, { x: 356, y: 216 });
  pressAt(p, { x: 356, y: 216 }, { dwell });
}

/** page.click()-style: pointer sat elsewhere for seconds, then ONE move straight to the centre, instant press. */
export function teleportClick(p: Page, dwell = 0): void {
  p.fire('pointermove', { ...sc({ x: 10, y: 10 }), pointerType: 'mouse' });
  p.wait(3000);
  p.fire('pointermove', { ...sc({ x: 350, y: 220 }), pointerType: 'mouse' });
  pressAt(p, { x: 350, y: 220 }, { dwell });
}

/** Playwright mouse.move(..., {steps}): evenly spaced linear steps in a few ms. */
export function linearSteps(p: Page, from: Pt, to: Pt, steps = 20, totalMs = 40): void {
  for (let i = 1; i <= steps; i++) {
    p.wait(totalMs / steps);
    p.fire('pointermove', { ...sc({ x: from.x + ((to.x - from.x) * i) / steps, y: from.y + ((to.y - from.y) * i) / steps }), pointerType: 'mouse' });
  }
}

/** Bézier + ease path as drawn by cursor-humanizing libraries; `jitter` randomises the event timing. */
export function bezierCursor(p: Page, from: Pt, to: Pt, o: { jitter: boolean; points?: number; stepMs?: number }): void {
  const n = o.points ?? 40;
  const c1 = { x: from.x + (to.x - from.x) * 0.2, y: from.y - 80 };
  const c2 = { x: from.x + (to.x - from.x) * 0.8, y: to.y + 60 };
  for (let i = 1; i <= n; i++) {
    const u = i / n;
    const t = u * u * (3 - 2 * u);
    const m = 1 - t;
    const x = m ** 3 * from.x + 3 * m * m * t * c1.x + 3 * m * t * t * c2.x + t ** 3 * to.x;
    const y = m ** 3 * from.y + 3 * m * m * t * c1.y + 3 * m * t * t * c2.y + t ** 3 * to.y;
    p.wait((o.stepMs ?? 16) + (o.jitter ? (p.rng() - 0.5) * 6 : 0));
    p.fire('pointermove', { ...sc({ x: x + (o.jitter ? (p.rng() - 0.5) * 1.5 : 0), y: y + (o.jitter ? (p.rng() - 0.5) * 1.5 : 0) }), pointerType: 'mouse' });
  }
  p.wait(o.jitter ? 60 + p.rng() * 80 : 50);
}

export function typeText(p: Page, text: string, o: { iki: () => number; hold: () => number }): void {
  for (const ch of text) {
    p.wait(o.iki());
    p.fire('keydown', { key: ch, code: 'Key' + ch.toUpperCase(), target: p.field });
    p.wait(o.hold());
    p.fire('input', { inputType: 'insertText', data: ch, target: p.field });
    p.fire('keyup', { key: ch, code: 'Key' + ch.toUpperCase(), target: p.field });
  }
}
