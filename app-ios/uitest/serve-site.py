#!/usr/bin/env python3
"""The UI tests' static site: the same directory over https and over plain http, on loopback only.

usage: serve-site.py <dir> <https port> <http port> <cert.pem> <key.pem>

A POST is answered with a page that says what was submitted (field names, a digest of each value, and a
one-time code), so a form submission navigates like a real sign-in, the browser's save offer has something
to follow, and a test can check what was submitted without the page showing a value.

POST /control/vault-create|vault-delete|vault-restore?name=… let a test act as another device of the test
account (tools/uitest-seed `vault`), to see what the app learns at its next sync. Both ports listen on loopback
only and the account is a throwaway one.
"""
import functools
import hashlib
import http.server
import os
import subprocess
import ssl
import sys
import threading
import time
import urllib.parse


class Handler(http.server.SimpleHTTPRequestHandler):
    # A connection that says nothing for this long is closed, so connections a browser opens ahead of time and then
    # abandons do not pile up, and a stalled TLS handshake ends with a line in the log instead of hanging.
    timeout = 20

    def do_POST(self):
        if self.path.startswith("/control/"):
            return self.control()
        length = int(self.headers.get("Content-Length") or 0)
        fields = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        names = ", ".join(sorted(fields)) or "nothing"
        # Each value as the first 16 hex digits of its SHA-256: a test compares them with its fixture (Fixture.digest),
        # and the page never shows a value itself.
        digests = ", ".join(
            "%s=%s" % (name, hashlib.sha256(values[0].encode("utf-8")).hexdigest()[:16]) for name, values in sorted(fields.items())
        ) or "nothing"
        # A one-time code is spent once it is submitted, so the page may show it; nothing else is echoed.
        code = (fields.get("code") or [""])[0]
        shown = "<p id=code>Code: %s</p>" % code if code.isdigit() and len(code) <= 8 else ""
        body = (
            "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Submitted</title><h1 id=done>Submitted</h1><p id=fields>Fields: %s</p><p id=digest>Digest: %s</p>%s"
            % (names, digests, shown)
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def control(self):
        parsed = urllib.parse.urlparse(self.path)
        action = {"/control/vault-create": "create", "/control/vault-delete": "delete", "/control/vault-restore": "restore"}.get(parsed.path)
        name = (urllib.parse.parse_qs(parsed.query).get("name") or [""])[0]
        if action is None or not name:
            self.send_error(404)
            return
        command = ["java", "-jar", os.environ["UITEST_SEED_JAR"], "vault", action, os.environ["UITEST_SERVER_ORIGIN"],
                   os.environ["UITEST_EMAIL"], os.environ["UITEST_PASSWORD"], name]
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=120)
            ok, out = done.returncode == 0, (done.stdout + done.stderr)[-2000:]
        except subprocess.TimeoutExpired:
            ok, out = False, "timed out"
        sys.stderr.write("control %s %r: %s\n" % (action, name, "ok" if ok else out))
        body = out.encode()
        self.send_response(200 if ok else 500)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


class Server(http.server.ThreadingHTTPServer):
    """One line per failed connection (a TLS alert, a reset, a timeout) instead of a traceback."""

    def handle_error(self, request, client_address):
        error = sys.exc_info()[1]
        sys.stderr.write("%s - - [%s] connection failed (%s:%d): %s: %s\n" % (
            client_address[0], time.strftime("%d/%b/%Y %H:%M:%S"), self.name, self.server_address[1],
            type(error).__name__, error))


def main():
    directory, https_port, http_port, cert, key = sys.argv[1:6]
    handler = functools.partial(Handler, directory=directory)
    secure = Server(("127.0.0.1", int(https_port)), handler)
    secure.name = "https"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)

    def server_name(sock, name, ctx):
        # Which name each TLS connection asked for: a name the certificate does not carry explains a rejection.
        sys.stderr.write("tls connection for %s at %s\n" % (name, time.strftime("%d/%b/%Y %H:%M:%S")))

    context.sni_callback = server_name
    # The handshake happens on the connection's own thread, at its first read: a client that connects and
    # says nothing must not hold up the accept loop.
    secure.socket = context.wrap_socket(secure.socket, server_side=True, do_handshake_on_connect=False)
    plain = Server(("127.0.0.1", int(http_port)), handler)
    plain.name = "http"
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    secure.serve_forever()


if __name__ == "__main__":
    main()
