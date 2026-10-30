import { requestInclusiveToken, type BioKynClientOptions } from './index.js';

export interface BioKynWidgetOptions extends BioKynClientOptions { label?: string; busyLabel?: string }

/** Register the optional `<biokyn-check>` web component. It emits `biokyn-token` on success and
 * `biokyn-error` on failure. It does not submit forms or make authorization decisions for the site. */
export function defineBioKynWidget(tagName = 'biokyn-check'): void {
  if (typeof customElements === 'undefined' || typeof HTMLElement === 'undefined') return;
  if (customElements.get(tagName)) return;
  class BioKynCheckElement extends HTMLElement {
    private button?: HTMLButtonElement;
    private status?: HTMLSpanElement;
    private controller?: AbortController;
    connectedCallback(): void {
      if (this.button) return;
      const root = this.attachShadow({ mode: 'open' });
      const style = document.createElement('style');
      style.textContent = ':host{display:inline-block;font:14px system-ui,sans-serif;color:var(--biokyn-color,#172033)}button{border:1px solid #aab4c4;border-radius:9px;background:var(--biokyn-bg,#fff);color:inherit;padding:10px 14px;font:inherit;cursor:pointer}button:disabled{opacity:.65;cursor:wait}span{display:block;margin-top:6px;font-size:12px}';
      const button = document.createElement('button'); button.type = 'button'; button.textContent = this.getAttribute('label') ?? 'Verify';
      const status = document.createElement('span'); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
      button.addEventListener('click', () => { void this.verify(button, status); });
      root.append(style, button, status); this.button = button; this.status = status;
    }
    disconnectedCallback(): void { this.controller?.abort(); this.controller = undefined; }
    private async verify(button: HTMLButtonElement, status: HTMLSpanElement): Promise<void> {
      if (button.disabled) return;
      this.controller?.abort(); this.controller = new AbortController(); button.disabled = true;
      button.textContent = this.getAttribute('busy-label') ?? 'Verifying…'; status.textContent = '';
      try {
        const result = await requestInclusiveToken({ basePath: this.getAttribute('base-path') ?? '/biokyn', signal: this.controller.signal });
        this.dispatchEvent(new CustomEvent('biokyn-token', { bubbles: true, composed: true, detail: { token: result.token } }));
        status.textContent = 'Verification completed.';
      } catch (error) {
        this.dispatchEvent(new CustomEvent('biokyn-error', { bubbles: true, composed: true, detail: { message: error instanceof Error ? error.message : 'Verification failed' } }));
        status.textContent = 'Could not verify. Please try again or use the site’s alternative.';
      } finally { button.disabled = false; button.textContent = this.getAttribute('label') ?? 'Verify'; }
    }
  }
  customElements.define(tagName, BioKynCheckElement);
}
