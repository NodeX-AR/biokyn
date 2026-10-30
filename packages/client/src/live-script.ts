/**
 * Browser collector for interaction liveness. `installLiveness` is SELF-CONTAINED on purpose (no imports, no
 * references to anything outside its own body): the served script is literally `(${installLiveness})(window, document)`,
 * so the code that runs in the browser is the code that is type-checked and unit-tested here.
 *
 * Privacy: raw coordinates and timestamps live only in a short in-memory ring buffer and are reduced to ~30 aggregate
 * integers (see NUM_FIELDS in liveness.ts) when a protected form is submitted. No key values, no field contents, no
 * network requests of its own, nothing leaves the page except those integers inside the form's own submission.
 */

interface LiveNode {
  hasAttribute?(name: string): boolean;
  contains?(other: unknown): boolean;
  getBoundingClientRect?(): { left: number; top: number; width: number; height: number };
  appendChild?(child: unknown): unknown;
  querySelector?(selector: string): { value?: string } | null;
}
interface LiveEvent {
  type: string;
  isTrusted?: boolean;
  timeStamp: number;
  clientX: number;
  clientY: number;
  screenX: number;
  screenY: number;
  pointerType?: string;
  button?: number;
  target?: LiveNode | null;
  key?: string;
  code?: string;
  repeat?: boolean;
  inputType?: string;
  data?: string | null;
  getCoalescedEvents?: () => unknown[];
}
interface LiveWindow {
  performance?: { now(): number };
  crypto?: { getRandomValues(a: Uint8Array): unknown };
  btoa(s: string): string;
  innerHeight?: number;
  outerHeight?: number;
  BioKynLive?: unknown;
}
interface LiveDocument {
  addEventListener(type: string, fn: (e: LiveEvent) => void, capture?: boolean): void;
  createElement(tag: string): { type?: string; name?: string; value?: string };
}

export function installLiveness(w: LiveWindow, d: LiveDocument): void {
  if (w.BioKynLive) return;
  const now = (): number => (w.performance ? w.performance.now() : Date.now());
  const APPROACH = 800;
  const MAX_SAMPLES = 160;
  const RUN_GAP = 3000;
  const FRESH = 1500;
  const NF = 27; // number of numeric report fields; must match NUM_FIELDS in liveness.ts

  // ---- state (in memory only) ----
  const st: number[] = [];
  const sx: number[] = [];
  const sy: number[] = [];
  const sc: number[] = [];
  let firstT = -1;
  const synthetic: Array<{ t: number; target: LiveNode | null | undefined }> = [];
  let lastCause: { t: number; target: LiveNode | null | undefined } | null = null;
  let lastEnter: { t: number; target: LiveNode | null | undefined } | null = null;
  const clicks: Array<{ t: number; x: number; y: number; dwell: number }> = [];
  const keyTimes: number[] = [];
  const holds: number[] = [];
  const down: Record<string, number> = {};
  let lastKeyT = -1e9;
  let bulk = 0;

  interface Press {
    t: number;
    x: number;
    y: number;
    type: string;
    target: LiveNode | null | undefined;
    screen: number;
    centerP: number;
    f: number[]; // approach features, see approach()
    dwell: number;
    drift: number;
    upT: number;
  }
  let press: Press | null = null;

  const hyp = (a: number, b: number): number => Math.sqrt(a * a + b * b);
  const seen = (t: number): void => { if (firstT < 0) firstT = t; };
  const inside = (form: LiveNode | null, n: LiveNode | null | undefined): boolean =>
    !form || !n || !form.contains || form.contains(n);
  const cv = (a: number[]): number => {
    if (a.length < 3) return -1;
    let m = 0;
    for (const v of a) m += v;
    m /= a.length;
    if (m <= 0) return -1;
    let q = 0;
    for (const v of a) q += (v - m) * (v - m);
    return Math.round((Math.sqrt(q / a.length) / m) * 1000);
  };

  /** Aggregates of the last 800 ms of trusted pointer motion before a press. All outputs are integers. */
  function approach(t: number, x: number, y: number): { f: number[] } {
    let i0 = st.length;
    for (let i = 0; i < st.length; i++) {
      if (st[i]! >= t - APPROACH && st[i]! <= t) { i0 = i; break; }
    }
    const win: number[] = [];
    for (let i = i0; i < st.length && st[i]! <= t; i++) win.push(i);
    let prev = -1;
    if (win.length > 0) prev = i0 - 1;
    else for (let i = st.length - 1; i >= 0; i--) if (st[i]! <= t) { prev = i; break; }
    const travel = prev >= 0 ? Math.round(hyp(x - sx[prev]!, y - sy[prev]!)) : -1;

    let span = 0, disp = 0, path = 0, peak = 0, peakPhase = 0, decel = 0, straight = 0, jump = 0, dtCv = -1, coal = 0;
    if (win.length >= 2) {
      const pt: number[] = [];
      const px: number[] = [];
      const py: number[] = [];
      for (const i of win) { pt.push(st[i]!); px.push(sx[i]!); py.push(sy[i]!); }
      const dts: number[] = [];
      for (let k = 1; k < pt.length; k++) dts.push(pt[k]! - pt[k - 1]!);
      dtCv = cv(dts.filter((v) => v > 0));
      if (pt[pt.length - 1]! < t) { pt.push(t); px.push(x); py.push(y); }
      const ds: number[] = [];
      const tt: number[] = [];
      for (let k = 1; k < pt.length; k++) {
        ds.push(hyp(px[k]! - px[k - 1]!, py[k]! - py[k - 1]!));
        tt.push(Math.max(pt[k]! - pt[k - 1]!, 0.5));
      }
      span = pt[pt.length - 1]! - pt[0]!;
      disp = hyp(px[px.length - 1]! - px[0]!, py[py.length - 1]! - py[0]!);
      let maxStep = 0, peakAt = 0;
      for (const v of ds) { path += v; if (v > maxStep) maxStep = v; }
      const W = Math.min(3, ds.length);
      for (let k = 0; k + W <= ds.length; k++) {
        let dd = 0, dt = 0;
        for (let j = k; j < k + W; j++) { dd += ds[j]!; dt += tt[j]!; }
        const sp = (dd / dt) * 1000;
        if (sp > peak) { peak = sp; peakAt = pt[k]! + dt / 2; }
      }
      peakPhase = span > 0 ? Math.max(0, Math.min(1000, Math.round(((peakAt - pt[0]!) / span) * 1000))) : 0;
      // Deceleration is measured from actual pointer-move samples only.  Do not let the
      // time between the final move and pointerdown look like a zero-speed segment: that
      // interval is user dwell/hover time, not pointer motion.
      const moveEnd = st[st.length - 1]!;
      let ld = 0, lt = 0;
      for (let k = 1; k < pt.length; k++) if (pt[k]! <= moveEnd && pt[k - 1]! >= moveEnd - 120) { ld += ds[k - 1]!; lt += tt[k - 1]!; }
      decel = peak > 0 && lt > 0 ? Math.min(1000, Math.round(((ld / lt) * 1000 / peak) * 1000)) : 0;
      straight = path > 0 ? Math.round((disp / path) * 1000) : 0;
      jump = path > 0 ? Math.round((maxStep / path) * 1000) : 0;
      let c = 0;
      for (const i of win) c += sc[i]!;
      coal = Math.round((c / win.length) * 10);
    }
    return { f: [win.length, Math.round(span), Math.round(disp), Math.round(path), Math.round(peak), peakPhase, decel, straight, jump, dtCv, coal, travel] };
  }

  // ---- event handlers ----
  const onMove = (e: LiveEvent): void => {
    if (e.isTrusted === false) return;
    seen(e.timeStamp);
    st.push(e.timeStamp); sx.push(e.clientX); sy.push(e.clientY);
    sc.push(e.getCoalescedEvents ? e.getCoalescedEvents().length : 0);
    if (st.length > MAX_SAMPLES) { st.splice(0, 32); sx.splice(0, 32); sy.splice(0, 32); sc.splice(0, 32); }
  };
  const onDown = (e: LiveEvent): void => {
    if (e.isTrusted === false) { synthetic.push({ t: e.timeStamp, target: e.target }); return; }
    if (e.button !== undefined && e.button !== 0) return;
    seen(e.timeStamp);
    const a = approach(e.timeStamp, e.clientX, e.clientY);
    const type = e.pointerType || 'mouse';
    let screen = 0;
    if (type === 'mouse' && (w.outerHeight || 0) - (w.innerHeight || 0) > 20) {
      screen = e.screenX - e.clientX === 0 && e.screenY - e.clientY === 0 ? 2 : 1;
    }
    let centerP = -1;
    const r = e.target && e.target.getBoundingClientRect ? e.target.getBoundingClientRect() : null;
    if (r && r.width > 0 && r.height > 0) {
      const off = hyp(e.clientX - (r.left + r.width / 2), e.clientY - (r.top + r.height / 2));
      centerP = Math.min(2000, Math.round((off / (hyp(r.width, r.height) / 2)) * 1000));
    }
    press = { t: e.timeStamp, x: e.clientX, y: e.clientY, type, target: e.target, screen, centerP, f: a.f, dwell: -1, drift: -1, upT: -1 };
  };
  const onUp = (e: LiveEvent): void => {
    if (e.isTrusted === false) { synthetic.push({ t: e.timeStamp, target: e.target }); return; }
    lastCause = { t: e.timeStamp, target: e.target };
    const p = press;
    if (!p || p.upT >= 0) return;
    p.upT = e.timeStamp;
    p.dwell = Math.round(e.timeStamp - p.t);
    p.drift = Math.round(hyp(e.clientX - p.x, e.clientY - p.y) * 10);
    const last = clicks[clicks.length - 1];
    if (last && p.t - last.t > RUN_GAP) clicks.length = 0;
    clicks.push({ t: p.t, x: p.x, y: p.y, dwell: p.dwell });
    if (clicks.length > 12) clicks.shift();
  };
  const onClick = (e: LiveEvent): void => {
    if (e.isTrusted === false) { synthetic.push({ t: e.timeStamp, target: e.target }); return; }
    lastCause = { t: e.timeStamp, target: e.target };
  };
  const MOD = { Shift: 1, Control: 1, Alt: 1, Meta: 1, CapsLock: 1, AltGraph: 1 } as Record<string, number>;
  const onKeyDown = (e: LiveEvent): void => {
    if (e.isTrusted === false || e.repeat || (e.key !== undefined && MOD[e.key] === 1)) return;
    seen(e.timeStamp);
    lastCause = { t: e.timeStamp, target: e.target };
    if (e.key === 'Enter' || e.key === ' ') lastEnter = { t: e.timeStamp, target: e.target };
    // Measure typing cadence from printable keys only. Including Enter/Tab in the
    // inter-key intervals creates a false non-metronomic outlier at submission.
    if (typeof e.key === 'string' && e.key.length === 1) {
      lastKeyT = e.timeStamp;
      const lastK = keyTimes[keyTimes.length - 1];
      if (lastK !== undefined && e.timeStamp - lastK > RUN_GAP) { keyTimes.length = 0; holds.length = 0; }
      keyTimes.push(e.timeStamp);
      if (keyTimes.length > 24) keyTimes.shift();
      down[e.code || e.key || '?'] = e.timeStamp;
    }
  };
  const onKeyUp = (e: LiveEvent): void => {
    if (e.isTrusted === false) return;
    const id = e.code || e.key || '?';
    const t0 = down[id];
    if (t0 !== undefined) { holds.push(Math.max(0, e.timeStamp - t0)); if (holds.length > 24) holds.shift(); delete down[id]; }
  };
  const onInput = (e: LiveEvent): void => {
    if (e.isTrusted === false) return;
    lastCause = { t: e.timeStamp, target: e.target };
    if (e.inputType === 'insertText' && typeof e.data === 'string' && e.data.length >= 8 && e.timeStamp - lastKeyT > 120) bulk++;
  };
  const onChange = (e: LiveEvent): void => { if (e.isTrusted !== false) lastCause = { t: e.timeStamp, target: e.target }; };

  // ---- report ----
  function report(form: LiveNode | null): string {
    const T = now();
    const fresh = (c: { t: number; target: LiveNode | null | undefined } | null): boolean => !!c && T - c.t < FRESH && inside(form, c.target);
    const p = press && press.upT >= 0 && T - press.upT < FRESH && inside(form, press.target) ? press : null;
    const enter = fresh(lastEnter) ? lastEnter : null;
    let src = 5;
    if (p && (!enter || p.upT >= enter.t)) src = p.type === 'touch' ? 3 : p.type === 'pen' ? 4 : 0;
    else if (enter) src = 1;
    else if (fresh(lastCause)) src = 2;

    let untrusted = 0;
    for (const s of synthetic) if (T - s.t < 3000 && inside(form, s.target)) untrusted++;

    const f = p && src !== 1 ? p.f : [0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1];
    let moves = f[0]!;
    if (src !== 0 && src !== 3 && src !== 4) {
      moves = 0;
      for (const t of st) if (T - t < 10000) moves++;
    }
    const pointer = src === 0 || src === 3 || src === 4;

    let clkInt = -1, clkJit = -1, clkDw = -1;
    if (clicks.length >= 3) {
      const iv: number[] = [];
      for (let i = 1; i < clicks.length; i++) iv.push(clicks[i]!.t - clicks[i - 1]!.t);
      clkInt = cv(iv);
      let m = 0;
      for (let i = 0; i < clicks.length; i++) for (let j = i + 1; j < clicks.length; j++) {
        m = Math.max(m, hyp(clicks[i]!.x - clicks[j]!.x, clicks[i]!.y - clicks[j]!.y));
      }
      clkJit = Math.round(m * 10);
      clkDw = cv(clicks.map((c) => c.dwell));
    }
    let ikiCv = -1, holdMean = -1, holdZero = -1;
    if (keyTimes.length >= 3) {
      const iv: number[] = [];
      for (let i = 1; i < keyTimes.length; i++) iv.push(keyTimes[i]! - keyTimes[i - 1]!);
      ikiCv = cv(iv);
    }
    if (holds.length >= 3) {
      let sum = 0, z = 0;
      for (const h of holds) { sum += h; if (h < 2) z++; }
      holdMean = Math.round(sum / holds.length);
      holdZero = Math.round((z / holds.length) * 1000);
    }

    const nums = [
      untrusted, Math.round(firstT >= 0 ? T - firstT : 0), moves,
      f[1]!, f[2]!, f[3]!, f[4]!, f[5]!, f[6]!, f[7]!, f[8]!, f[9]!, f[10]!, pointer ? f[11]! : -1,
      pointer && p ? p.dwell : -1, pointer && p ? p.drift : -1, pointer && p ? p.centerP : -1, pointer && p ? p.screen : 0,
      clicks.length, clkInt, clkJit, clkDw, keyTimes.length, ikiCv, holdMean, holdZero, bulk,
    ];
    if (nums.length !== NF) throw new Error('liveness: field count mismatch');

    const salt = new Uint8Array(6);
    if (w.crypto) w.crypto.getRandomValues(salt);
    else for (let i = 0; i < salt.length; i++) salt[i] = Math.floor(Math.random() * 256);
    let saltS = '';
    for (const b of salt) saltS += String.fromCharCode(b);
    const toUrl = (s: string): string => w.btoa(s).split('+').join('-').split('/').join('_').split('=').join('');
    return 'bl1.' + toUrl(JSON.stringify([1, src, ...nums, toUrl(saltS)]));
  }

  function attach(form: LiveNode): void {
    const value = report(form);
    let input = form.querySelector ? form.querySelector('input[name=_biokyn_live]') : null;
    if (!input) {
      const created = d.createElement('input');
      created.type = 'hidden';
      created.name = '_biokyn_live';
      if (form.appendChild) form.appendChild(created);
      input = created;
    }
    input.value = value;
  }

  // Capture phase on the document: runs before page handlers, cannot be pre-empted by stopPropagation below it.
  d.addEventListener('pointermove', onMove, true);
  d.addEventListener('pointerdown', onDown, true);
  d.addEventListener('pointerup', onUp, true);
  d.addEventListener('mousedown', (e) => { if (e.isTrusted === false) synthetic.push({ t: e.timeStamp, target: e.target }); }, true);
  d.addEventListener('mouseup', (e) => { if (e.isTrusted === false) synthetic.push({ t: e.timeStamp, target: e.target }); }, true);
  d.addEventListener('click', onClick, true);
  d.addEventListener('keydown', onKeyDown, true);
  d.addEventListener('keyup', onKeyUp, true);
  d.addEventListener('input', onInput, true);
  d.addEventListener('change', onChange, true);
  d.addEventListener('submit', (e) => {
    const f = e.target;
    if (f && f.hasAttribute && f.hasAttribute('data-biokyn')) attach(f);
  }, true);

  w.BioKynLive = {
    version: 1,
    /** For custom submissions that call form.submit(), explicitly attach before sending; submit() skips DOM submit events. */
    /** Report string for a custom (fetch/XHR) submission: send it as header `x-biokyn-live`. */
    report: (form?: LiveNode | null): string => report(form || null),
    attach,
  };
}

/** Served at `${basePath}/live.js`. */
/**
 * The served script is the function's own source text, so any helper a build tool injects into function bodies would be
 * an undefined free variable in the browser. esbuild's `keepNames` (used by tsx, Vite SSR, some Next.js setups) injects
 * `__name(...)` calls; the wrapper below defines that one helper as an identity function. Build the published package with plain `tsc` (the supported configuration);
 * coverage instrumentation and aggressive minifiers also inject helpers.
 */
export const LIVENESS_SCRIPT = `(function(){var __name=function(t){return t};(${installLiveness.toString()})(window,document);})();`;

export function livenessScriptTag(basePath = '/__biokyn'): string {
  const esc = basePath.replace(/[^A-Za-z0-9/_.-]/g, '');
  return `<script src="${esc}/live.js" defer></script>`;
}
