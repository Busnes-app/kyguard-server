import './theme';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { finishKeyring } from './vault';

// Keep registration in the bundled script so script-src 'self' permits it.
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    void navigator.serviceWorker.register('/sw.js').catch(() => {});
  }, { once: true });
}

async function render() {
  const notice = await finishKeyring().catch((err: unknown) =>
    err instanceof Error ? err.message : 'KyIdentity keyring sign-in failed.');
  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <App initialNotice={notice} />
    </React.StrictMode>
  );
}

void render();
