import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

STATE = "/run/fake"
CANARY = "rt-canary-vm-7c1e9f3a2b"
lock = threading.Lock()


def mode():
    try:
        with open(f"{STATE}/mode") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "ok"


def bump(name):
    with lock:
        path = f"{STATE}/{name}"
        n = int(open(path).read()) + 1 if os.path.exists(path) else 1
        with open(path, "w") as f:
            f.write(str(n))
        return n


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, body):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply(200, json.dumps({"host": self.headers.get("Host")}))

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if self.headers.get("Content-Type", "").startswith("application/json"):
            form = json.loads(raw)
        else:
            form = {k: v[0] for k, v in parse_qs(raw).items()}
        grant = form.get("grant_type")
        if grant == "authorization_code":
            n = bump("logins")
            self.reply(200, json.dumps({
                "access_token": f"at-login-{n}",
                "refresh_token": f"{CANARY}-0",
                "expires_in": int(open(f"{STATE}/login_expires_in").read()) if os.path.exists(f"{STATE}/login_expires_in") else 3600,
            }))
            return
        n = bump("posts")
        with open(f"{STATE}/last_refresh", "w") as f:
            f.write(form.get("refresh_token", ""))
        m = mode()
        if m == "slow":
            time.sleep(2)
        if m == "hang":
            while mode() == "hang":
                time.sleep(0.1)
            self.reply(200, json.dumps({"access_token": "at-killed", "refresh_token": f"{CANARY}-killed", "expires_in": 3600}))
            return
        if m == "refuse-echo":
            self.reply(400, json.dumps({"error": "invalid_grant", "error_description": f"refresh token {form.get('refresh_token')} revoked"}))
            return
        if m == "fail-echo":
            self.reply(502, f"upstream: refresh_token={form.get('refresh_token')}")
            return
        expires = int(open(f"{STATE}/expires_in").read()) if os.path.exists(f"{STATE}/expires_in") else 3600
        self.reply(200, json.dumps({"access_token": f"at-{n}", "refresh_token": f"{CANARY}-{n}", "expires_in": expires}))


os.makedirs(STATE, exist_ok=True)
srv = ThreadingHTTPServer(("0.0.0.0", 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
