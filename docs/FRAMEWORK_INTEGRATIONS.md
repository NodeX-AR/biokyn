# Framework integration notes

## React

Register the web component once in a client-only module. React can render the custom element and subscribe to native events using a ref:

```tsx
'use client';
import { useEffect, useRef } from 'react';
import { defineBioKynWidget } from '@biokyn/client';
export function BioKynCheck({ onToken }: { onToken: (token: string) => void }) {
  const ref = useRef<HTMLElement>(null);
  useEffect(() => {
    defineBioKynWidget();
    const el = ref.current;
    const handler = (e: Event) => onToken((e as CustomEvent<{token:string}>).detail.token);
    el?.addEventListener('biokyn-token', handler);
    return () => el?.removeEventListener('biokyn-token', handler);
  }, [onToken]);
  return <biokyn-check ref={ref} base-path="/biokyn" />;
}
```

For TypeScript JSX, declare `JSX.IntrinsicElements['biokyn-check']` in the app's custom-element typings if your React version requires it. Never verify a token with a secret in the browser.

## Vue / Svelte

Register `defineBioKynWidget()` in a browser-only entry point. Listen to the native `biokyn-token` event and forward `event.detail.token` to your server endpoint. In SSR, do not access `customElements` during server rendering. Framework wrappers should remain thin and should not store the secret or make the authorization decision client-side.

## Next.js

Use a client component for the widget and a server route/action to verify the returned token. Configure the server route with shared nullifier/attempt stores and rate limiting. Do not rely on a client-only check to protect a server action.

## Edge runtimes

The generic HTTP handler is not a blanket guarantee of edge compatibility: runtime support depends on cryptographic APIs, package bundling and Node-specific references. Run integration tests in the exact target runtime before deployment. JA4/TLS metadata must be supplied by a trusted edge proxy that strips untrusted inbound copies.
