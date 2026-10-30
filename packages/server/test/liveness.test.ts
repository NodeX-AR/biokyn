import { describe, expect, it } from 'vitest';
import {
  DEFAULT_THRESHOLDS, NUM_FIELDS, decodeReport, encodeReport, judgeLiveness, MAX_REPORT_CHARS, type LivenessReport,
} from '../src/liveness.js';
import { LIVENESS_SCRIPT } from '../../client/src/live-script.js';
import {
  bezierCursor, createPage, humanApproach, humanClick, linearSteps, pressAt, teleportClick, typeText,
} from './page.js';

const judge = (r: LivenessReport) => judgeLiveness(r);
const ids = (r: LivenessReport) => judge(r).signals.map((s) => s.id);

describe('report codec', () => {
  it('round-trips and rejects malformed input', () => {
    const p = createPage();
    humanClick(p);
    const raw = p.submit();
    const r = decodeReport(raw)!;
    expect(r).not.toBeNull();
    expect(encodeReport(r)).toBe(raw);
    expect(raw.length).toBeLessThan(MAX_REPORT_CHARS);
    for (const bad of ['', 'x', 'bl1.', 'bl1.!!!', 'bl1.' + Buffer.from('[1]').toString('base64url'), raw.slice(0, -4), 'bl2.' + raw.slice(4), raw + 'A'.repeat(800)]) {
      expect(decodeReport(bad)).toBeNull();
    }
    const arr = JSON.parse(Buffer.from(raw.slice(4), 'base64url').toString());
    arr[5] = 1.5;
    expect(decodeReport('bl1.' + Buffer.from(JSON.stringify(arr)).toString('base64url'))).toBeNull();
    arr[5] = -2;
    expect(decodeReport('bl1.' + Buffer.from(JSON.stringify(arr)).toString('base64url'))).toBeNull();
  });
  it('wire order matches the collector (27 numeric fields)', () => {
    expect(NUM_FIELDS).toHaveLength(27);
  });
});

describe('browser script (the real served code, run in an isolated vm)', () => {
  it('is self-contained: only window and document are needed', () => {
    expect(() => createPage()).not.toThrow();
    expect(LIVENESS_SCRIPT.startsWith('(')).toBe(true);
    console.log(`live.js size: ${Buffer.byteLength(LIVENESS_SCRIPT)} bytes; report size: ${(() => { const p = createPage(); humanClick(p); return p.rawLength(); })()} chars`);
  });
  it('report() on a full page of events is fast (<5 ms)', () => {
    const p = createPage();
    for (let i = 0; i < 3; i++) humanApproach(p, { x: 10, y: 10 }, { x: 600, y: 400 });
    humanClick(p);
    const t0 = performance.now();
    for (let i = 0; i < 50; i++) p.submit();
    const per = (performance.now() - t0) / 50;
    console.log(`report build: ${per.toFixed(3)} ms per submit`);
    expect(per).toBeLessThan(5);
  });
  it('does not touch fields of unrelated forms and sets one hidden input', () => {
    const p = createPage();
    humanClick(p);
    p.submit();
    const first = p.form.querySelector();
    p.submit();
    expect(p.form.querySelector()).toBe(first); // same input reused, value refreshed
  });
});

describe('humans', () => {
  it.each([1, 2, 3, 4, 5])('mouse user (seed %i) -> human_like with zero signals', (seed) => {
    const p = createPage({ seed });
    humanClick(p, { x: 40 + seed * 30, y: 400 + seed * 20 }, 70 + seed * 12);
    const r = p.report();
    expect(r.src).toBe('pointer');
    expect(judge(r)).toMatchObject({ verdict: 'human_like', score: 0 });
    expect(r.untrusted).toBe(0);
  });
  it('mouse at 1000 Hz and at 60 Hz are both human_like', () => {
    for (const hz of [60, 1000]) {
      const p = createPage({ seed: 9 });
      humanApproach(p, { x: 80, y: 500 }, { x: 356, y: 216 }, { hz });
      pressAt(p, { x: 356, y: 216 }, { dwell: 90 });
      expect(judge(p.report()).verdict).toBe('human_like');
    }
  });
  it('pointer resting on the button (no recent movement) is not a teleport', () => {
    const p = createPage();
    humanApproach(p, { x: 80, y: 500 }, { x: 356, y: 216 });
    p.wait(3000); // user reads the page, then clicks without moving
    pressAt(p, { x: 356, y: 216 });
    const r = p.report();
    expect(r.moves).toBe(0);
    expect(ids(r)).not.toContain('teleport');
    expect(judge(r).verdict).not.toBe('automation');
  });
  it('repeated human clicking (varied rhythm, drifting position, varied dwell) is not metronomic', () => {
    const p = createPage({ seed: 4 });
    humanClick(p);
    for (let i = 0; i < 7; i++) {
      p.wait(180 + p.rng() * 400);
      pressAt(p, { x: 356 + (p.rng() - 0.5) * 14, y: 216 + (p.rng() - 0.5) * 10 }, { dwell: 60 + p.rng() * 70 });
    }
    expect(judge(p.report()).verdict).not.toBe('automation');
  });
  it('touch tap is never penalised and is classified touch', () => {
    const p = createPage();
    pressAt(p, { x: 350, y: 220 }, { pointerType: 'touch', dwell: 70 });
    const r = p.report();
    expect(r.src).toBe('touch');
    expect(judge(r).verdict).toBe('unknown');
  });
  it('keyboard-only user (Tab, typing, Enter) -> unknown, never automation', () => {
    const p = createPage({ seed: 3 });
    p.fire('keydown', { key: 'Tab', code: 'Tab', target: p.field });
    p.fire('keyup', { key: 'Tab', code: 'Tab', target: p.field });
    typeText(p, 'hello world', { iki: () => 90 + p.rng() * 220, hold: () => 60 + p.rng() * 60 });
    p.wait(300);
    p.fire('keydown', { key: 'Enter', code: 'Enter', target: p.field });
    p.fire('keyup', { key: 'Enter', code: 'Enter', target: p.field });
    const r = p.report();
    expect(r.src).toBe('keyboard');
    expect(judge(r).verdict).toBe('unknown');
    expect(judge(r).score).toBe(0);
  });
  it('screen-reader / switch activation (trusted click, detail 0, no pointer) is unknown, not automation', () => {
    const p = createPage();
    p.fire('click', { detail: 0, target: p.btn });
    const r = p.report();
    expect(r.src).toBe('virtual');
    expect(judge(r)).toMatchObject({ verdict: 'unknown', score: 0 });
  });
  it('extension/page-script synthetic events elsewhere do not count against the user', () => {
    const p = createPage();
    p.fire('click', { isTrusted: false, target: p.elsewhere }); // e.g. a widget calling fileInput.click()
    p.fire('keydown', { isTrusted: false, key: 'a', target: p.field }); // password-manager fill
    p.fire('input', { isTrusted: false, inputType: 'insertText', data: 'hunter2hunter2', target: p.field });
    humanClick(p);
    const r = p.report();
    expect(r.untrusted).toBe(0);
    expect(r.bulk).toBe(0);
    expect(judge(r).verdict).toBe('human_like');
  });
  it('a human who typed by autocomplete/IME still gets at most a soft signal', () => {
    const p = createPage();
    p.fire('input', { inputType: 'insertText', data: 'supercalifragilistic', target: p.field }); // suggestion tap
    humanClick(p);
    const j = judge(p.report());
    expect(j.score).toBe(2);
    expect(j.verdict).not.toBe('automation');
  });
});

describe('automation that the signals catch', () => {
  it('Playwright page.click(): teleport + instant press + dead-centre', () => {
    const p = createPage();
    teleportClick(p, 0);
    const r = p.report();
    expect(judge(r).verdict).toBe('automation');
    expect(ids(r)).toEqual(expect.arrayContaining(['teleport', 'instant_click', 'dead_center']));
  });
  it('xdotool-style (mousemove then click with ~2 ms press) is caught', () => {
    const p = createPage();
    teleportClick(p, 2);
    expect(judge(p.report()).verdict).toBe('automation');
  });
  it('Playwright mouse.move steps=20 in 40 ms: superhuman speed', () => {
    const p = createPage();
    p.fire('pointermove', { clientX: 10, clientY: 10, screenX: 110, screenY: 160, pointerType: 'mouse' });
    p.wait(2000);
    linearSteps(p, { x: 10, y: 10 }, { x: 356, y: 216 }, 20, 40);
    pressAt(p, { x: 356, y: 216 }, { dwell: 1 });
    const r = p.report();
    expect(ids(r)).toContain('superhuman_speed');
    expect(judge(r).verdict).toBe('automation');
  });
  it('constant-velocity straight line at human speed is caught', () => {
    const p = createPage();
    linearSteps(p, { x: 20, y: 400 }, { x: 356, y: 216 }, 40, 800);
    p.wait(20);
    pressAt(p, { x: 356, y: 216 }, { dwell: 80 });
    const r = p.report();
    expect(r.moves).toBeGreaterThanOrEqual(8);
    expect(r.straightP).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.lineStraightP);
    expect(r.decelP).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.lineDecelP);
    expect(ids(r)).toEqual(expect.arrayContaining(['constant_velocity_line']));
    expect(judge(r).verdict).toBe('automation');
  });
  it('element.click() / dispatchEvent from a script: synthetic trigger and no trusted cause', () => {
    const p = createPage();
    p.fire('pointerdown', { isTrusted: false, button: 0 });
    p.fire('pointerup', { isTrusted: false });
    p.fire('click', { isTrusted: false, detail: 1 });
    const r = p.report();
    expect(r.src).toBe('none');
    expect(r.untrusted).toBeGreaterThan(0);
    expect(judge(r).verdict).toBe('automation');
  });
  it('form.requestSubmit() with no interaction at all: no_trigger', () => {
    const p = createPage();
    p.wait(4000);
    const r = p.report();
    expect(r.src).toBe('none');
    expect(ids(r)).toContain('no_trigger');
    expect(judge(r).verdict).toBe('automation');
  });
  it('constant-interval autoclicker', () => {
    const p = createPage();
    for (let i = 0; i < 8; i++) { pressAt(p, { x: 350, y: 220 }, { dwell: 10 }); p.wait(90); }
    const r = p.report();
    expect(ids(r)).toContain('metronomic_clicks');
    expect(judge(r).verdict).toBe('automation');
  });
  it('randomised-interval autoclicker is caught by identical position + constant dwell', () => {
    const p = createPage({ seed: 11 });
    for (let i = 0; i < 8; i++) {
      p.fire('pointerdown', { clientX: 350, clientY: 220, screenX: 450, screenY: 370, pointerType: 'mouse', button: 0 });
      p.wait(12);
      p.fire('pointerup', { clientX: 350, clientY: 220, screenX: 450, screenY: 370, pointerType: 'mouse', button: 0 });
      p.fire('click', { detail: 1 });
      p.wait(60 + p.rng() * 200);
    }
    const r = p.report();
    expect(r.clkIntCvP).toBeGreaterThan(120); // intervals really are irregular
    expect(ids(r)).toEqual(expect.arrayContaining(['identical_click_position', 'constant_click_dwell']));
    expect(judge(r).verdict).toBe('automation');
  });
  it('scripted typing: metronomic keys with zero hold', () => {
    const p = createPage();
    typeText(p, 'hello world!', { iki: () => 50, hold: () => 0 });
    p.fire('keydown', { key: 'Enter', code: 'Enter', target: p.field });
    const r = p.report();
    expect(ids(r)).toEqual(expect.arrayContaining(['metronomic_keys', 'zero_key_hold']));
    expect(judge(r).verdict).toBe('automation');
  });
  it('page.fill() (bulk insert) followed by page.click()', () => {
    const p = createPage();
    p.fire('input', { inputType: 'insertText', data: 'attacker@example.com', target: p.field });
    teleportClick(p, 0);
    const r = p.report();
    expect(r.bulk).toBe(1);
    expect(judge(r).verdict).toBe('automation');
  });
});

describe('documented limits (these pass, by design of what is observable)', () => {
  it('Bézier cursor with fixed 16 ms ticks is only a soft signal (unknown, not human_like)', () => {
    const p = createPage();
    bezierCursor(p, { x: 80, y: 500 }, { x: 356, y: 216 }, { jitter: false });
    pressAt(p, { x: 356, y: 216 }, { dwell: 70 });
    const j = judge(p.report());
    expect(j.signals.map((s) => s.id)).toContain('uniform_timing');
    expect(j.verdict).toBe('unknown');
  });
  it('an agent that emulates human paths, timing jitter, dwell and off-centre presses is human_like', () => {
    const p = createPage({ seed: 8 });
    bezierCursor(p, { x: 80, y: 500 }, { x: 356, y: 216 }, { jitter: true });
    pressAt(p, { x: 358, y: 213 }, { dwell: 75 });
    expect(judge(p.report()).verdict).toBe('human_like');
  });
  it('thresholds are overridable per deployment', () => {
    const p = createPage();
    teleportClick(p, 0);
    const r = p.report();
    expect(judgeLiveness(r, { ...DEFAULT_THRESHOLDS, teleportPx: 100000 }, 100).verdict).toBe('unknown');
  });
});
