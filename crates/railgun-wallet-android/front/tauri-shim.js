// Makes the unchanged desktop front run over Tauri IPC: every `fetch("/api/...")` of index.html
// becomes `invoke("api", { path, body })`. Loaded before the app script (see build-dist.sh).
(function () {
  const invoke = window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke;
  if (!invoke) return; // served by the daemon: leave fetch alone.

  const json = (value, status) =>
    new Response(JSON.stringify(value), {
      status,
      headers: { "content-type": "application/json" },
    });

  const realFetch = window.fetch.bind(window);

  window.fetch = async function (input, init) {
    const url = typeof input === "string" ? input : input && input.url;
    if (typeof url !== "string" || !url.startsWith("/api/")) return realFetch(input, init);

    const [path, query] = url.split("?");
    let body = null;
    if (init && typeof init.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        return json({ error: "bad request body" }, 400);
      }
    } else if (query) {
      // `/api/logs?since=3` and friends: the dispatch accepts the query as an object.
      body = Object.fromEntries(new URLSearchParams(query));
    }

    try {
      return json(await invoke("api", { path, body }), 200);
    } catch (e) {
      // `ApiFailure` from src/lib.rs, or a plain string when the IPC itself failed.
      if (e && typeof e === "object" && typeof e.code === "number") {
        return json({ error: e.error }, e.code);
      }
      return json({ error: typeof e === "string" ? e : "ipc call failed" }, 503);
    }
  };
})();
