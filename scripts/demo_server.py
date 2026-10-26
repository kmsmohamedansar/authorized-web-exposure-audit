#!/usr/bin/env python3
"""Fake localhost-only site for the authorized exposure audit demonstration."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PAGES = {
    "/": (
        "text/html; charset=utf-8",
        b"""<!doctype html><html><head><title>Demo Corp</title></head>
<body><h1>Deliberately vulnerable demo</h1>
<a href="/public/quarterly-plan.pdf">Quarterly plan</a>
<script src="/assets/app.js"></script></body></html>""",
    ),
    "/assets/app.js": (
        "application/javascript; charset=utf-8",
        b"""// Fake demonstration values; not usable credentials.
const apiBase = '/api/v1/catalog';
const api_key = 'DEMO_ONLY_NOT_A_REAL_SECRET_123456789';
fetch('/graphql');
""",
    ),
    "/openapi.json": (
        "application/json; charset=utf-8",
        b'{"openapi":"3.0.0","info":{"title":"Demo API","version":"1"},"paths":{"/api/v1/catalog":{}}}',
    ),
    "/robots.txt": (
        "text/plain; charset=utf-8",
        b"User-agent: *\nAllow: /\nSitemap: http://127.0.0.1:8765/sitemap.xml\n",
    ),
    "/sitemap.xml": (
        "application/xml; charset=utf-8",
        b'<urlset><url><loc>http://127.0.0.1:8765/public/quarterly-plan.pdf</loc></url></urlset>',
    ),
    "/.well-known/security.txt": (
        "text/plain; charset=utf-8",
        b"Contact: mailto:security@example.invalid\nExpires: 2099-12-31T23:59:59Z\n",
    ),
}


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "ExposureAuditDemo/1.0"

    def do_GET(self) -> None:  # noqa: N802
        content_type, body = PAGES.get(self.path, ("text/plain; charset=utf-8", b"Not found\n"))
        status = 200 if self.path in PAGES else 404
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"demo: {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the localhost-only fake exposure fixture")
    parser.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "::1", "localhost"))
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"Fake demo listening on http://{args.host}:{server.server_port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

