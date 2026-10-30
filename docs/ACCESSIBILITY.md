# Accessibility

## What the code now guarantees (verified by review and unit tests, **not by user studies**)

- No lane requires motion. The only token paths are Argon2id proof-of-work (no user interaction at all) and a registered WebAuthn credential.
- The optional motion check is an *escalation aid* and its dialog provides: `role=dialog`/`aria-modal`, `aria-labelledby`/`aria-describedby`, focus moved
  into the dialog and restored on close, Tab trapped inside, Escape cancels, 44×44 px minimum targets, a live-region status, no flashing or animation
  (so `prefers-reduced-motion` is satisfied), colour contrast ≥ 7:1 for text, and a first-class **"Use the alternative check instead"** button
  (`outcome: 'alternative'`) that integrators must wire to `requestInclusiveToken`.
- Keyboard-only, screen-reader and switch users generate no pointer evidence; the server treats absent kinematics as neutral (they follow the PoW lane).
- The `<biokyn-check>` component uses a native `<button>` and a polite live region.

## What has NOT been established

Real assistive-technology behaviour (NVDA/JAWS/VoiceOver/TalkBack/Dragon/switch), cognitive load, PoW latency on low-end devices (battery, throttled
CPUs), and whether the advisory motion check wrongly escalates users with tremor or one-handed/trackball use. These need a study.

## Study protocol (required before the accessibility gate can be checked)

1. **Participants:** ≥ 5 per group, recruited with disability organisations, compensated: screen-reader (≥ 2 products), magnification/low vision, keyboard-only,
   switch/voice control, motor impairment (tremor/limited range), cognitive/learning disability, older adults, low-end mobile devices.
2. **Tasks:** complete a form protected by the PoW lane; trigger the escalated dialog and complete via the alternative; (if enabled) register and use a WebAuthn credential.
3. **Measures:** completion rate, time, errors, abandonment, SUS, think-aloud blockers; PoW wall-clock on the participant's own device.
4. **Automated checks:** axe-core/pa11y on every state of the dialog and widget; manual WCAG 2.2 AA review (2.1.1 keyboard, 2.4.3 focus order, 2.5.8 target size, 3.3.8 accessible authentication, 4.1.3 status messages).
5. **Exit criteria:** no blocker severity; completion ≥ 95 % per group through at least one lane; documented mitigation for every remaining issue.
