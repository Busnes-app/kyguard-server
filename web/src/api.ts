function cookieValue(name: string): string {
  const prefix = `${encodeURIComponent(name)}=`;
  const item = document.cookie.split('; ').find((part) => part.startsWith(prefix));
  return item ? decodeURIComponent(item.slice(prefix.length)) : '';
}

function send(input: RequestInfo | URL, init: RequestInit): Promise<Response> {
  const headers = new Headers(init.headers);
  // On https the server names it __Host-ky_csrf (a sibling host cannot plant it).
  const csrf = cookieValue('__Host-ky_csrf') || cookieValue('ky_csrf');
  if (csrf) headers.set('X-CSRF-Token', csrf);
  return fetch(input, { ...init, headers });
}

let reStepUp: (() => Promise<boolean>) | null = null;

// onStepupStale registers the shell's prompt for a fresh authenticator code. It resolves true
// once /api/auth/stepup/totp accepted one, false when the user cancels.
export function onStepupStale(prompt: (() => Promise<boolean>) | null): void {
  reStepUp = prompt;
}

// secureFetch sends the CSRF token. A privileged route whose step-up window has passed answers
// 403 stepup_stale (spec §7.3 rule 6): the user is asked for a code, and on success the request
// is sent once more.
export async function secureFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const response = await send(input, init);
  if (response.status !== 403 || !reStepUp) return response;
  const body: unknown = await response.clone().json().catch(() => null);
  const stale = typeof body === 'object' && body !== null && 'code' in body && body.code === 'stepup_stale';
  if (!stale || !(await reStepUp())) return response;
  return send(input, init);
}
