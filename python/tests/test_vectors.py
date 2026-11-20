import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading
import time

from wavpub_crawler_verify import (
    CODE_CIRCUIT_OPEN,
    CODE_INVALID_TOKEN,
    CODE_OK,
    OfflineVerifier,
    OnlineVerifier,
)

VECTORS_PATH = Path(__file__).resolve().parents[2] / "spec" / "vectors.json"


def test_shared_vectors_offline():
    data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    verifier = OfflineVerifier.from_jwks(json.dumps(data["jwks"]))

    for tc in data["cases"]:
        res = verifier.verify(
            token=tc["token"],
            host=tc["host"],
            scope=tc["scope"],
            now_unix=tc["now_unix"],
        )
        assert res.valid == tc["want_valid"], tc["name"]
        assert res.code == tc["want_code"], tc["name"]
        assert res.host == tc["want_host"], tc["name"]
        if tc.get("want_scope"):
            assert res.scope == tc["want_scope"], tc["name"]
        if tc.get("want_kid"):
            assert res.kid == tc["want_kid"], tc["name"]


def test_online_verifier_cache_and_ip_circuit():
    data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    valid_token = data["cases"][0]["token"]
    calls = {"n": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            calls["n"] += 1
            if f"token={valid_token}" in self.path and "host=feed.xyzcdn.net" in self.path:
                body = json.dumps({
                    "valid": True,
                    "code": CODE_OK,
                    "host": "feed.xyzcdn.net",
                    "scope": "rss",
                    "expires_at": int(time.time()) + 300,
                    "ttl_seconds": 300,
                }).encode("utf-8")
                self.send_response(200)
            else:
                body = json.dumps({
                    "valid": False,
                    "code": CODE_INVALID_TOKEN,
                    "host": "feed.xyzcdn.net",
                }).encode("utf-8")
                self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        ov = OnlineVerifier(verify_url=f"http://127.0.0.1:{port}/api/request-verify")
        r1 = ov.verify(valid_token, "FEED.XYZCDN.NET", "rss", client_ip="1.2.3.4")
        r2 = ov.verify(valid_token, "feed.xyzcdn.net", "rss", client_ip="1.2.3.4")
        assert r1.valid and r2.valid and calls["n"] == 1

        for _ in range(3):
            ov.verify("bad.token", "feed.xyzcdn.net", "rss", client_ip="9.9.9.9")
        before = calls["n"]
        blocked = ov.verify(valid_token, "feed.xyzcdn.net", "rss", client_ip="9.9.9.9")
        assert not blocked.valid and blocked.code == CODE_CIRCUIT_OPEN and calls["n"] == before
    finally:
        srv.shutdown()
