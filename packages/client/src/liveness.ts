/**
 * Interaction liveness: a local, instant, popup-free signal that the action which triggered a submission
 * (click, tap, Enter) was produced by plausible human input rather than by a script, an autoclicker or a
 * browser-driving agent.
 *
 * The browser collector (live-script.ts) watches pointer/keyboard events ON THE PAGE and, when a protected form is
 * submitted, attaches a compact report of aggregate numbers (no coordinates, no timestamps, no key values) to the
 * same request. Nothing is sent to a third party and no extra request is made. This module decodes the report and
 * judges it on YOUR server, so thresholds can change without redeploying clients.
 *
 * HONEST SCOPE (also in docs/LIVENESS.md):
 *  - It catches common automation: synthetic events, one-step "teleport" mouse moves (what page.click() and xdotool
 *    produce), zero-dwell clicks, superhuman speed, constant-velocity straight lines, metronomic autoclickers and
 *    bulk programmatic typing.
 *  - It does NOT stop an agent that deliberately emulates human pointer paths and timing, nor an attacker who forges
 *    the report: client-side evidence is always forgeable. It raises cost; it is not proof of humanity.
 *  - Unknown is not guilty: keyboard, screen-reader, switch and voice users produce no pointer approach and are
 *    classified `unknown`, which is never rejected unless you opt in.
 */
export interface LivenessStore { setNx(key: string, ttlMs: number): Promise<boolean>; }

export const REPORT_PREFIX = 'bl1.';
export const MAX_REPORT_CHARS = 700;

export const SOURCES = ['pointer', 'keyboard', 'virtual', 'touch', 'pen', 'none'] as const;
export type LivenessSource = (typeof SOURCES)[number];

/** Order is the wire order. -1 means "not observed". */
export const NUM_FIELDS = [
  'untrusted', // synthetic (isTrusted=false) pointer/click events on the submitted form
  'obsMs', // time the collector has been observing
  'moves', // trusted pointermove events in the 800 ms before pointerdown
  'spanMs',
  'dispPx',
  'pathPx',
  'peakSpeed', // px/s
  'peakPhaseP', // where the speed peak falls in the approach, permille
  'decelP', // speed in the last 120 ms relative to the peak, permille
  'straightP', // displacement / path, permille
  'jumpP', // largest single step / path, permille
  'dtCvP', // coefficient of variation of inter-move times, permille
  'coalX10', // mean coalesced events per pointermove ×10
  'travelPx', // distance from the last known pointer position (before the approach) to the press point
  'dwellMs', // pointerdown -> pointerup
  'driftX10', // pointer drift during the press ×10 px
  'centerP', // click offset from the target's centre / half-diagonal, permille
  'screen', // 0 unknown, 1 consistent, 2 inconsistent screenX/Y vs clientX/Y
  'clicks', // length of the current click run
  'clkIntCvP',
  'clkJitterX10',
  'clkDwellCvP',
  'keys', // length of the current keystroke run
  'ikiCvP',
  'holdMeanMs',
  'holdZeroP', // share of key holds < 2 ms, permille
  'bulk', // trusted insertText bursts with no keystrokes
] as const;
export type NumField = (typeof NUM_FIELDS)[number];

export type LivenessReport = { src: LivenessSource; salt: string } & Record<NumField, number>;

const b64uDecode = (s: string): string => { const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/')); let out=''; for(const c of bin) out += String.fromCharCode(c.charCodeAt(0)); return decodeURIComponent(escape(out)); };
const b64uEncode = (s: string): string => { const bin = unescape(encodeURIComponent(s)); let out=''; for(let i=0;i<bin.length;i++) out += String.fromCharCode(bin.charCodeAt(i)); return btoa(out).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); };

export function encodeReport(r: LivenessReport): string {
  const arr: Array<number | string> = [1, SOURCES.indexOf(r.src), ...NUM_FIELDS.map((k) => r[k]), r.salt];
  return REPORT_PREFIX + b64uEncode(JSON.stringify(arr));
}

/** Strict decoder: any structural or range violation returns null (the caller treats that as malformed). */
export function decodeReport(raw: string): LivenessReport | null {
  if (typeof raw !== 'string' || raw.length > MAX_REPORT_CHARS || !raw.startsWith(REPORT_PREFIX)) return null;
  const body = raw.slice(REPORT_PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(body)) return null;
  let arr: unknown;
  try {
    arr = JSON.parse(b64uDecode(body));
  } catch {
    return null;
  }
  if (!Array.isArray(arr) || arr.length !== NUM_FIELDS.length + 3 || arr[0] !== 1) return null;
  const srcCode = arr[1];
  if (typeof srcCode !== 'number' || !Number.isInteger(srcCode) || srcCode < 0 || srcCode >= SOURCES.length) return null;
  const salt = arr[arr.length - 1];
  if (typeof salt !== 'string' || !/^[A-Za-z0-9_-]{6,16}$/.test(salt)) return null;
  const out = { src: SOURCES[srcCode]!, salt } as LivenessReport;
  for (let i = 0; i < NUM_FIELDS.length; i++) {
    const v = arr[2 + i];
    if (typeof v !== 'number' || !Number.isFinite(v) || !Number.isInteger(v) || v < -1 || v > 100_000_000) return null;
    out[NUM_FIELDS[i]!] = v;
  }
  return out;
}

/* --------------------------------- judgment -------------------------------- */

export interface LivenessThresholds {
  /** Press point this far from the last known pointer position, reached in <= 2 moves, is a teleport. */
  teleportPx: number;
  /** Faster than any human pointer approach (px/s). */
  maxPeakSpeed: number;
  /** Mouse press shorter than this is instant (ms). */
  instantDwellMs: number;
  shortDwellMs: number;
  /** Click run: interval CV (permille) below this is metronomic. */
  metronomeCvP: number;
  minClickRun: number;
  minKeyRun: number;
  keyMetronomeCvP: number;
  /** Straight, constant-velocity approach. */
  lineStraightP: number;
  lineDecelP: number;
  uniformDtCvP: number;
  /** Dead-centre click tolerance, permille of half-diagonal. */
  centerP: number;
}

/** Provisional engineering values: validate against YOUR traffic in `monitor` mode before enforcing. */
export const DEFAULT_THRESHOLDS: LivenessThresholds = {
  teleportPx: 40,
  maxPeakSpeed: 8000,
  instantDwellMs: 5,
  shortDwellMs: 20,
  metronomeCvP: 60,
  minClickRun: 4,
  minKeyRun: 8,
  keyMetronomeCvP: 50,
  lineStraightP: 997,
  lineDecelP: 850,
  uniformDtCvP: 25,
  centerP: 8,
};

export type LivenessVerdict = 'human_like' | 'unknown' | 'automation';

export interface Signal { id: string; weight: number }
export interface LivenessJudgment { verdict: LivenessVerdict; score: number; signals: Signal[] }

/**
 * Weighted, transparent rules (no model, so nothing opaque to audit). `automation` when the weights reach
 * `automationScore`; `human_like` only with positive pointer-approach evidence and no signals; otherwise `unknown`.
 */
export function judgeLiveness(r: LivenessReport, t: LivenessThresholds = DEFAULT_THRESHOLDS, automationScore = 4): LivenessJudgment {
  const s: Signal[] = [];
  const add = (id: string, weight: number): void => { s.push({ id, weight }); };

  if (r.untrusted > 0) add('synthetic_trigger', 3);
  // Keep this mirror aligned with server judgment: no observed trigger is a risk signal.
  if (r.src === 'none') add('no_trigger', 4);

  if (r.src === 'pointer') {
    if (r.moves <= 2 && r.travelPx >= t.teleportPx) add('teleport', 4);
    if (r.dwellMs >= 0 && r.dwellMs < t.instantDwellMs) add('instant_click', 3);
    else if (r.dwellMs >= 0 && r.dwellMs < t.shortDwellMs) add('very_short_click', 1);
    if (r.moves >= 3 && r.peakSpeed > t.maxPeakSpeed) add('superhuman_speed', 3);
    if (r.moves >= 8 && r.straightP >= t.lineStraightP && r.decelP >= 0 && r.decelP >= t.lineDecelP) add('constant_velocity_line', 3);
    if (r.moves >= 10 && r.dtCvP >= 0 && r.dtCvP < t.uniformDtCvP) add('uniform_timing', 2);
    if (r.centerP >= 0 && r.centerP < t.centerP && r.moves <= 3) add('dead_center', 2);
    if (r.screen === 2) add('screen_mismatch', 2);
  } else if (r.src === 'touch') {
    if (r.dwellMs >= 0 && r.dwellMs < t.instantDwellMs) add('instant_tap', 2);
  }

  if (r.clicks >= t.minClickRun) {
    if (r.clkIntCvP >= 0 && r.clkIntCvP < t.metronomeCvP) add('metronomic_clicks', 4);
    if (r.clicks >= 6 && r.clkJitterX10 === 0) add('identical_click_position', 3);
    if (r.clkDwellCvP >= 0 && r.clkDwellCvP < 30) add('constant_click_dwell', 2);
  }
  if (r.keys >= t.minKeyRun) {
    if (r.ikiCvP >= 0 && r.ikiCvP < t.keyMetronomeCvP) add('metronomic_keys', 3);
    if (r.holdZeroP >= 900) add('zero_key_hold', 2);
  }
  if (r.bulk > 0) add('bulk_insert', 2);

  const score = s.reduce((a, x) => a + x.weight, 0);
  let verdict: LivenessVerdict = 'unknown';
  if (score >= automationScore) verdict = 'automation';
  else if (score === 0 && r.src === 'pointer' && r.moves >= 6 && r.dwellMs >= t.shortDwellMs) verdict = 'human_like';
  return { verdict, score, signals: s };
}

/* ------------------------------ engine options ----------------------------- */

export interface LivenessOptions {
  /**
   * off: ignore. monitor (default): judge and report via onDecision, never reject.
   * enforce: reject `automation` (and, with requireReport, requests that carry no report).
   */
  mode?: 'off' | 'monitor' | 'enforce';
  /** Reject requests with no liveness report. Default: true in enforce mode. */
  requireReport?: boolean;
  /** Weight sum at which a request is judged `automation`. Default 4. */
  automationScore?: number;
  thresholds?: Partial<LivenessThresholds>;
  /** Also reject `unknown` (keyboard/assistive/no-approach) sessions. Default false: unknown is never punished. */
  rejectUnknown?: boolean;
  /** Server-side log hook. NEVER forward this to the client: it is the anti-oracle boundary. */
  onDecision?: (d: LivenessDecision) => void;
}

export interface LivenessDecision {
  mode: 'monitor' | 'enforce';
  verdict: LivenessVerdict | 'missing' | 'malformed' | 'replayed';
  score: number;
  signals: Signal[];
  /** True when this decision caused the request to be rejected. */
  rejected: boolean;
  formId: string;
  action: string;
  report?: LivenessReport;
}

export interface ResolvedLiveness {
  mode: 'off' | 'monitor' | 'enforce';
  requireReport: boolean;
  automationScore: number;
  thresholds: LivenessThresholds;
  rejectUnknown: boolean;
  onDecision?: ((d: LivenessDecision) => void) | undefined;
}

export function resolveLiveness(o: LivenessOptions | undefined): ResolvedLiveness {
  const mode = o?.mode ?? 'monitor';
  return {
    mode,
    requireReport: o?.requireReport ?? mode === 'enforce',
    automationScore: o?.automationScore ?? 4,
    thresholds: { ...DEFAULT_THRESHOLDS, ...o?.thresholds },
    rejectUnknown: o?.rejectUnknown ?? false,
    onDecision: o?.onDecision,
  };
}

/** Each exact report may be submitted once (they carry a random salt), so a captured human report cannot be replayed. */
export async function claimReport(store: LivenessStore, rawReport: string, ttlMs: number, sha256Hex: (v: string) => string): Promise<boolean> {
  return store.setNx(`lv:${sha256Hex(rawReport)}`, ttlMs);
}
