interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

declare const Go: new () => GoRuntime;
declare const kyGuardVault: (input: string) => string;
declare function importScripts(...urls: string[]): void;

let runtime: Promise<void> | undefined;

async function load(): Promise<void> {
  importScripts('/assets/wasm_exec.js');
  const go = new Go();
  const response = await fetch('/assets/vault-crypto.wasm', { redirect: 'error', cache: 'no-store' });
  const result = await WebAssembly.instantiateStreaming(response, go.importObject);
  void go.run(result.instance).catch(() => self.close());
}

self.onmessage = async (event: MessageEvent<{ id: number; input: object }>) => {
  // The browser dispatches dedicated-worker messages with an empty origin.
  if (!event.isTrusted || event.origin !== '') return;

  const { id, input } = event.data;
  try {
    runtime ??= load();
    await runtime;
    const output: unknown = JSON.parse(kyGuardVault(JSON.stringify(input)));
    self.postMessage({ id, output });
  } catch {
    runtime = undefined;
    self.postMessage({ id, output: { error: 'The trusted browser vault client could not load.' } });
  }
};
