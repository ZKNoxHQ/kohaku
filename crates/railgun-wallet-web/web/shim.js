// Railgun wallet web: the daemon's front talks to `/api/…` as with the local daemon; these calls
// are answered by the wasm engine in worker.js instead of the network. Everything else (RPC,
// subsquid, POI node, bundler, Waku) is fetched directly by the worker or the page.
(function () {
  const worker = new Worker(new URL("./worker.js", document.baseURI), { type: "module" });
  const pending = new Map();
  let seq = 0;

  worker.onmessage = (event) => {
    const { id, ok, body, error } = event.data;
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    if (ok) p.resolve(body);
    else p.reject(new Error(error));
  };
  worker.onerror = (event) => {
    const msg = "engine worker failed: " + (event.message || "see the console");
    console.error("Railgun wallet:", msg, event);
    for (const p of pending.values()) p.reject(new Error(msg));
    pending.clear();
  };

  // A Ledger unlock: the permission picker only exists on the main thread and needs the click's
  // user gesture, so grant USB access here; the worker then opens the device with getDevices().
  const LEDGER_VENDOR_ID = 0x2c97;
  async function grantUsb(body) {
    let params;
    try { params = JSON.parse(body || "{}"); } catch { return; }
    if (!params.ledger || (params.ledgerTransport || "usb") !== "usb") return;
    if (!navigator.usb) throw new Error("WebUSB is not available in this browser (use Chromium)");
    const devices = await navigator.usb.getDevices();
    if (devices.some((d) => d.vendorId === LEDGER_VENDOR_ID)) return;
    await navigator.usb.requestDevice({ filters: [{ vendorId: LEDGER_VENDOR_ID }] })
      .catch((e) => { throw new Error("Ledger USB access: " + (e && e.message ? e.message : e)); });
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const raw = typeof input === "string" ? input : input && input.url;
    const url = new URL(raw, location.href);
    const at = url.pathname.indexOf("/api/");
    if (url.origin !== location.origin || at < 0) return realFetch(input, init);
    const path = url.pathname.slice(at) + url.search;
    const method = ((init && init.method) || "GET").toUpperCase();
    const body = init && typeof init.body === "string" ? init.body : "";
    const gate = path.startsWith("/api/unlock") && method === "POST" ? grantUsb(body) : Promise.resolve();
    const id = ++seq;
    return gate.then(() => new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, method, path, body });
    })).then((text) => new Response(text, { status: 200, headers: { "content-type": "application/json" } }));
  };
})();
