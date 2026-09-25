// Railgun wallet web: the wasm engine runs here, off the page's main thread (scans, proofs and
// note decryption take a while). One message per `/api/…` request forwarded by shim.js.
import init, { api } from "./pkg/railgun_wallet_web.js";

const ready = init();

self.onmessage = async (event) => {
  const { id, method, path, body } = event.data;
  try {
    await ready;
    const out = await api(method, path, body || "");
    self.postMessage({ id, ok: true, body: out });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String((err && err.message) || err) });
  }
};
