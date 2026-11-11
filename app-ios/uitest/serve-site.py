#!/usr/bin/env python3
"""The UI tests' static site: the same directory over https and over plain http, on loopback only.

usage: serve-site.py <dir> <https port> <http port> <cert.pem> <key.pem>

A POST is answered with a page that says what was submitted (field names, and a one-time code), so a
form submission navigates like a real sign-in and the browser's save offer has something to follow.
"""
import functools
import http.server
import ssl
import sys
import threading
import urllib.parse


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        fields = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        names = ", ".join(sorted(fields)) or "nothing"
        # A one-time code is spent once it is submitted, so the page may show it; nothing else is echoed.
        code = (fields.get("code") or [""])[0]
        shown = "<p id=code>Code: %s</p>" % code if code.isdigit() and len(code) <= 8 else ""
        body = (
            "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Submitted</title><h1 id=done>Submitted</h1><p id=fields>Fields: %s</p>%s" % (names, shown)
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main():
    directory, https_port, http_port, cert, key = sys.argv[1:6]
    handler = functools.partial(Handler, directory=directory)
    secure = http.server.ThreadingHTTPServer(("127.0.0.1", int(https_port)), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    # The handshake happens on the connection's own thread, at its first read: a client that connects and
    # says nothing must not hold up the accept loop.
    secure.socket = context.wrap_socket(secure.socket, server_side=True, do_handshake_on_connect=False)
    plain = http.server.ThreadingHTTPServer(("127.0.0.1", int(http_port)), handler)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    secure.serve_forever()


if __name__ == "__main__":
    main()
