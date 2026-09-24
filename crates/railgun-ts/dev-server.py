#!/usr/bin/env python3
"""Dev server for the browser wallet test page.

Serves crates/railgun-ts as static files with Cache-Control: no-store (so mobile
Chrome never serves a stale wasm build), and proxies POST /poi ->
https://ppoi.fdi.network/ over the desktop's working IPv4 (the POI host's IPv6 is
dead, which the phone's browser cannot get past)."""
import http.server
import urllib.error
import urllib.request

POI_UPSTREAM = "https://ppoi.fdi.network/"


class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.end_headers()

    def do_POST(self):
        if self.path.rstrip("/") != "/poi":
            self.send_response(404)
            self.end_headers()
            return
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        req = urllib.request.Request(
            POI_UPSTREAM, data=body, method="POST",
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as up:
                data, status = up.read(), up.status
        except urllib.error.HTTPError as e:
            data, status = e.read(), e.code
        except Exception as e:  # noqa: BLE001
            data, status = str(e).encode(), 502
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)


http.server.ThreadingHTTPServer.allow_reuse_address = True
with http.server.ThreadingHTTPServer(("127.0.0.1", 8000), H) as httpd:
    print("serving crates/railgun-ts on http://127.0.0.1:8000 (+ /poi proxy)")
    httpd.serve_forever()
