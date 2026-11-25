import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, execFileSync } from 'node:child_process';
import { accountsFile } from './totp.mjs';

// Always own disposable data. Never reuse a running development/production server.
const dir = await mkdtemp(join(tmpdir(), 'ky-browser-'));
const binary = fileURLToPath(new URL('../../.browser/server', import.meta.url));
const env = {
  PATH: process.env.PATH,
  KY_APP_URL: 'http://127.0.0.1:5391',
  KY_HOST: '127.0.0.1', KY_PORT: '5391', KY_DB_DRIVER: 'sqlite',
  KY_DATA_DIR: join(dir, 'data'), KY_BACKUP_DIR: join(dir, 'backups'),
  KY_CAPTCHA_PROVIDER: 'none',
};
// No bootstrap admin exists: create the break-glass accounts on the host, as an operator would.
// One for the shared signed-in state (setup.mjs), one per project for the UI sign-in, because a
// TOTP code is single-use. That is the deployment's limit of five.
const accounts = {};
for (const name of ['admin', 'op-light-390', 'op-light-1280', 'op-dark-390', 'op-dark-1280']) {
  const out = execFileSync(binary, ['break-glass', 'create', '-username', name], { cwd: dir, env, encoding: 'utf8' });
  accounts[name] = { password: out.match(/^Password: (\S+)$/m)[1], secret: out.match(/[?&]secret=([A-Z2-7]+)/)[1] };
}
await writeFile(accountsFile, JSON.stringify(accounts), { mode: 0o600 });
const server = spawn(binary, [], { cwd: dir, env, stdio: 'inherit' });
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.kill('SIGTERM'));
server.on('error', async error => { console.error(error.message); await rm(dir, { recursive: true, force: true }); process.exit(1); });
server.on('exit', async code => { await rm(dir, { recursive: true, force: true }); await rm(accountsFile, { force: true }); process.exit(code ?? 1); });
