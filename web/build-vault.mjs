import { cpSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const toolchain = /^toolchain (go[\d.]+)$/m.exec(readFileSync('../go.mod', 'utf8'))?.[1];
if (!toolchain) throw new Error('Missing pinned Go toolchain in go.mod');
const env = { ...process.env, GOTOOLCHAIN: toolchain, GOOS: 'js', GOARCH: 'wasm' };
rmSync('vault-dist', { recursive: true, force: true });
cpSync('dist', 'vault-dist', { recursive: true });
mkdirSync('vault-dist/assets', { recursive: true });
execFileSync('go', ['build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w',
  '-o', 'vault-dist/assets/vault-crypto.wasm', '../cmd/browser-vault'], { env, stdio: 'inherit' });
const goroot = execFileSync('go', ['env', 'GOROOT'], { env, encoding: 'utf8' }).trim();
cpSync(join(goroot, 'lib/wasm/wasm_exec.js'), 'vault-dist/assets/wasm_exec.js');
cpSync(join(goroot, 'LICENSE'), 'vault-dist/GO-LICENSE');
