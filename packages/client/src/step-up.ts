/**
 * Optional motion check shown only after the SERVER escalated a request.
 *
 * Security stance: the numbers produced here are chosen by code running on the visitor's machine, so they are
 * forgeable. They are submitted to the server purely as an untrusted risk signal; this function does not decide
 * "passed", the server never answers "passed", and nothing here can mint a token. The only server-verifiable lanes
 * are the Argon2id proof-of-work (requestInclusiveToken) and a registered-credential WebAuthn assertion.
 *
 * Accessibility: the dialog is labelled and described, traps focus, restores focus on close, is dismissable with Escape,
 * has 44px minimum targets, and offers an explicit non-motion alternative button. Callers MUST handle the
 * `alternative` outcome by running the proof-of-work lane; motion must never be the only way through.
 */
export type MotionOutcome = 'completed' | 'cancelled' | 'timeout' | 'alternative';
export interface MotionMetrics { samples: number; corrections: number; pathRatioMilli: number; speedCvMilli: number }
export interface MotionStepUpResult extends MotionMetrics {
  /** Always 'client-untrusted'. Do not use any field here as an authorization decision. */
  trust: 'client-untrusted';
  outcome: MotionOutcome;
  modality: 'touch' | 'pointer';
  durationMs: number;
  server?: { status: 'MOTION_RECEIVED' } | { error: string };
}
export interface MotionStepUpOptions {
  title?: string; instruction?: string; alternativeLabel?: string; cancelLabel?: string;
  timeoutMs?: number;
  /** Fresh challenge from GET /biokyn/challenge. When omitted nothing is sent to the server. */
  challengeId?: string;
  /** Defaults to /biokyn/motion-step-up. */
  endpoint?: string;
}
export interface MotionPoint { x: number; y: number; t: number }

/** Pure metric extraction (unit-tested without a DOM). */
export function computeMotionMetrics(points: readonly MotionPoint[], corrections: number): MotionMetrics {
  const speeds: number[] = []; let dist = 0;
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1]!, b = points[i]!;
    const d = Math.hypot(b.x - a.x, b.y - a.y); dist += d;
    speeds.push(d / Math.max(1, b.t - a.t));
  }
  const mean = speeds.reduce((s, v) => s + v, 0) / Math.max(1, speeds.length);
  const variance = speeds.reduce((s, v) => s + (v - mean) ** 2, 0) / Math.max(1, speeds.length);
  const direct = points.length > 1 ? Math.hypot(points[points.length - 1]!.x - points[0]!.x, points[points.length - 1]!.y - points[0]!.y) : 0;
  return {
    samples: points.length, corrections,
    pathRatioMilli: Math.round((dist / Math.max(1, direct)) * 1000),
    speedCvMilli: Math.round((Math.sqrt(variance) / Math.max(0.001, mean)) * 1000),
  };
}

const style = (el: HTMLElement, css: Partial<CSSStyleDeclaration>): void => { Object.assign(el.style, css); };

export function runMotionStepUp(options: MotionStepUpOptions = {}): Promise<MotionStepUpResult> {
  if (typeof document === 'undefined' || typeof window === 'undefined') return Promise.reject(new Error('Motion step-up requires a browser'));
  return new Promise((resolve) => {
    const started = performance.now();
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const points: MotionPoint[] = [];
    let gestureStart = 0, down = false, pointerId: number | null = null, finished = false, corrections = 0, lastTurn = 0;

    const overlay = document.createElement('div');
    overlay.setAttribute('role', 'dialog'); overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'biokyn-step-title'); overlay.setAttribute('aria-describedby', 'biokyn-step-desc');
    style(overlay, { position: 'fixed', inset: '0', zIndex: '2147483647', background: 'rgba(5,8,18,.96)', color: '#f8fafc', display: 'grid', placeItems: 'center', fontFamily: 'system-ui,sans-serif', padding: '20px' });
    const panel = document.createElement('section'); panel.tabIndex = -1;
    style(panel, { width: 'min(92vw,420px)', padding: '24px', border: '1px solid #475569', borderRadius: '20px', background: '#0f172a', textAlign: 'center', outline: 'none' });
    const title = document.createElement('h2'); title.id = 'biokyn-step-title'; title.textContent = options.title ?? 'Additional security check';
    const desc = document.createElement('p'); desc.id = 'biokyn-step-desc';
    desc.textContent = options.instruction ?? 'Drag from the blue dot to the green square. Small corrections are fine. If you cannot use a pointer, choose the alternative check below.';
    const area = document.createElement('div'); area.setAttribute('role', 'img'); area.setAttribute('aria-label', 'Drag area: move from the blue dot to the green square. Use the alternative check button if you cannot drag.');
    style(area, { position: 'relative', width: 'min(72vw,300px)', height: 'min(72vw,300px)', maxHeight: '300px', margin: '18px auto', background: '#111c31', border: '1px solid #94a3b8', borderRadius: '16px', touchAction: 'none' });
    const dot = document.createElement('div'); style(dot, { position: 'absolute', left: '12%', top: '72%', width: '22px', height: '22px', borderRadius: '50%', background: '#38bdf8' });
    const target = document.createElement('div'); style(target, { position: 'absolute', right: '12%', top: '12%', width: '30px', height: '30px', border: '2px solid #4ade80', borderRadius: '8px', boxSizing: 'border-box' });
    const status = document.createElement('p'); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite'); status.textContent = 'Press and drag to begin.';
    const btnCss = { minHeight: '44px', minWidth: '44px', padding: '10px 18px', margin: '4px', borderRadius: '10px', border: '1px solid #94a3b8', background: '#1e293b', color: '#fff', cursor: 'pointer', font: 'inherit' } as const;
    const alt = document.createElement('button'); alt.type = 'button'; alt.textContent = options.alternativeLabel ?? 'Use the alternative check instead'; style(alt, btnCss);
    const cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = options.cancelLabel ?? 'Cancel'; style(cancel, btnCss);
    area.append(dot, target); panel.append(title, desc, area, status, alt, cancel); overlay.append(panel); document.body.append(overlay);
    panel.focus();

    const finish = (outcome: MotionOutcome): void => {
      if (finished) return; finished = true;
      area.removeEventListener('pointerdown', onDown); area.removeEventListener('pointermove', onMove); area.removeEventListener('pointerup', onUp); area.removeEventListener('pointercancel', onAbort);
      alt.removeEventListener('click', onAlt); cancel.removeEventListener('click', onAbort); overlay.removeEventListener('keydown', onKey); window.clearTimeout(timer);
      overlay.remove(); if (previouslyFocused && typeof previouslyFocused.focus === 'function') previouslyFocused.focus();
      const result: MotionStepUpResult = {
        trust: 'client-untrusted', outcome, modality: window.matchMedia?.('(pointer: coarse)').matches ? 'touch' : 'pointer',
        durationMs: Math.round(performance.now() - started), ...computeMotionMetrics(points, corrections),
      };
      if (outcome !== 'completed' || !options.challengeId) { resolve(result); return; }
      void fetch(options.endpoint ?? '/biokyn/motion-step-up', {
        method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: options.challengeId, modality: result.modality, durationMs: result.durationMs, samples: result.samples, corrections: result.corrections, pathRatioMilli: result.pathRatioMilli, speedCvMilli: result.speedCvMilli }),
      }).then(async (response) => {
        const body = await response.json() as { status?: string; error?: string };
        result.server = response.ok && body.status === 'MOTION_RECEIVED' ? { status: 'MOTION_RECEIVED' } : { error: typeof body.error === 'string' ? body.error : 'motion_step_up_failed' };
      }).catch((e: unknown) => { result.server = { error: e instanceof Error ? e.message : 'motion_step_up_failed' }; }).finally(() => resolve(result));
    };

    function onDown(e: PointerEvent): void {
      if (finished) return; gestureStart = performance.now(); down = true; pointerId = e.pointerId; points.length = 0; corrections = 0; lastTurn = 0;
      area.setPointerCapture?.(e.pointerId);
      const r = area.getBoundingClientRect(); points.push({ x: e.clientX - r.left, y: e.clientY - r.top, t: performance.now() });
      status.textContent = 'Keep dragging toward the green square.';
    }
    function onMove(e: PointerEvent): void {
      if (!down || e.pointerId !== pointerId || finished) return;
      const r = area.getBoundingClientRect(); const p = { x: e.clientX - r.left, y: e.clientY - r.top, t: performance.now() }; const prev = points[points.length - 1];
      if (prev) { const sign = Math.sign((p.x - prev.x) * (r.height * 0.6) - (p.y - prev.y) * (r.width * 0.6)); if (sign && lastTurn && sign !== lastTurn) corrections++; if (sign) lastTurn = sign; }
      if (points.length < 500) points.push(p);
      if (Math.hypot(p.x - (r.width * 0.88 - 15), p.y - (r.height * 0.12 + 15)) < 28 && performance.now() - gestureStart > 0) { down = false; finish('completed'); }
    }
    function onUp(): void { down = false; }
    function onAbort(): void { finish('cancelled'); }
    function onAlt(): void { finish('alternative'); }
    function onKey(e: KeyboardEvent): void {
      if (e.key === 'Escape') { e.preventDefault(); finish('cancelled'); return; }
      if (e.key !== 'Tab') return;
      const focusables = [alt, cancel]; const i = focusables.indexOf(document.activeElement as HTMLButtonElement);
      if (e.shiftKey && i <= 0) { e.preventDefault(); focusables[focusables.length - 1]!.focus(); }
      else if (!e.shiftKey && (i === focusables.length - 1)) { e.preventDefault(); focusables[0]!.focus(); }
      else if (i === -1) { e.preventDefault(); focusables[e.shiftKey ? focusables.length - 1 : 0]!.focus(); }
    }
    area.addEventListener('pointerdown', onDown); area.addEventListener('pointermove', onMove); area.addEventListener('pointerup', onUp); area.addEventListener('pointercancel', onAbort);
    alt.addEventListener('click', onAlt); cancel.addEventListener('click', onAbort); overlay.addEventListener('keydown', onKey);
    const timer = window.setTimeout(() => finish('timeout'), options.timeoutMs ?? 30_000);
  });
}
