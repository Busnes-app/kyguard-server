import { request, expect } from '@playwright/test';
import { accounts, adminState, totp } from './totp.mjs';

// One real break-glass sign-in (password + TOTP code) with its reason given, saved for the
// specs that need a signed-in shell. ui.spec.mjs signs in through the form itself.
export default async function setup(config) {
  const api = await request.newContext({ baseURL: config.projects[0].use.baseURL });
  try {
    await api.get('/');
    const { admin } = accounts();
    const login = await api.post('/api/auth/login', { data: { username: 'admin', password: admin.password, totp_code: totp(admin.secret) } });
    expect(login.ok(), await login.text()).toBe(true);
    const csrf = (await api.storageState()).cookies.find(cookie => cookie.name === 'ky_csrf')?.value;
    expect(csrf).toBeTruthy();
    const reason = await api.post('/api/auth/break-glass/reason', { headers: { 'X-CSRF-Token': csrf }, data: { reason: 'browser regression run' } });
    expect(reason.ok(), await reason.text()).toBe(true);
    await api.storageState({ path: adminState });
  } finally { await api.dispose(); }
}
