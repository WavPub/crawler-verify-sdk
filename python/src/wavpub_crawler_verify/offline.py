from __future__ import annotations

import json
import threading
import time
from typing import Dict, Optional, Set, Tuple
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .common import (
    ALG_EDDSA,
    CLOCK_SKEW_SEC,
    CODE_EXPIRED,
    CODE_HOST_MISMATCH,
    CODE_INVALID_HOST,
    CODE_INVALID_SCOPE,
    CODE_INVALID_TOKEN,
    CODE_OK,
    CODE_REVOKED,
    CODE_SCOPE_MISMATCH,
    DEFAULT_JWKS_URL,
    ISSUER,
    VALID_SCOPES,
    VerifyResult,
    b64url_decode,
    normalize_host,
    parse_compact_jwt,
)


class OfflineVerifier:
    """0 RTT 本地 Ed25519 JWKS 离线验签器。

    特性：
      - 后台线程按 poll_interval（默认 5 分钟）携带 If-None-Match 异步轮询 JWKS（304 零带宽）
      - 遇到未知 kid 时实行「unknown_kid_cooldown（默认 60s）+ 单飞锁」拉取最新公钥，防随机 kid 反射攻击
      - 拉取 200 后全量替换本地公钥表并应用 revoked_kids，同时清空有效缓存
      - 严格锁定 alg == "EdDSA"，校验 iss / aud / scp / iat-30<=now<exp
    """

    def __init__(
        self,
        jwks_url: str = DEFAULT_JWKS_URL,
        poll_interval: float = 300.0,
        unknown_kid_cooldown: float = 60.0,
        timeout: float = 3.0,
        start_background: bool = True,
        initial_jwks: Optional[bytes] = None,
    ) -> None:
        self.jwks_url = jwks_url
        self.poll_interval = max(10.0, poll_interval)
        self.unknown_kid_cooldown = max(0.0, unknown_kid_cooldown)
        self.timeout = timeout

        self._lock = threading.RLock()
        self._keys: Dict[str, Ed25519PublicKey] = {}
        self._revoked: Set[str] = set()
        self._etag: str = ""
        self._last_refresh: float = 0.0
        self._valid_cache: Dict[Tuple[str, str, str], VerifyResult] = {}
        self._refresh_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        if initial_jwks is not None:
            self.load_jwks(initial_jwks)
        elif self.jwks_url:
            try:
                self.refresh()
            except Exception:
                pass
            if start_background:
                self._thread = threading.Thread(target=self._poll_loop, daemon=True)
                self._thread.start()

    @classmethod
    def from_jwks(cls, jwks_json: bytes | str) -> "OfflineVerifier":
        raw = jwks_json.encode("utf-8") if isinstance(jwks_json, str) else jwks_json
        return cls(jwks_url="", start_background=False, initial_jwks=raw)

    def close(self) -> None:
        self._stop_event.set()

    def _poll_loop(self) -> None:
        while not self._stop_event.wait(self.poll_interval):
            try:
                self.refresh()
            except Exception:
                pass

    def load_jwks(self, raw: bytes | str) -> None:
        doc = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
        revoked = {str(k) for k in (doc.get("revoked_kids") or []) if str(k)}
        keys: Dict[str, Ed25519PublicKey] = {}
        for item in doc.get("keys") or []:
            if item.get("kty") != "OKP" or item.get("crv") != "Ed25519":
                continue
            kid = str(item.get("kid") or "")
            if not kid or kid in revoked:
                continue
            try:
                pub_bytes = b64url_decode(str(item.get("x") or ""))
                if len(pub_bytes) == 32:
                    keys[kid] = Ed25519PublicKey.from_public_bytes(pub_bytes)
            except Exception:
                continue

        with self._lock:
            self._keys = keys
            self._revoked = revoked
            self._last_refresh = time.time()
            self._valid_cache.clear()

    def refresh(self) -> None:
        if not self.jwks_url:
            return
        with self._lock:
            etag = self._etag
        headers = {}
        if etag:
            headers["If-None-Match"] = etag
        req = urllib.request.Request(self.jwks_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(1 << 20)
                new_etag = resp.headers.get("ETag") or ""
                self.load_jwks(body)
                if new_etag:
                    with self._lock:
                        self._etag = new_etag
        except urllib.error.HTTPError as e:
            if e.code == 304:
                with self._lock:
                    self._last_refresh = time.time()
                return
            raise

    def _refresh_if_cooled_down(self) -> None:
        if not self.jwks_url:
            return
        now = time.time()
        with self._lock:
            if self._last_refresh and (now - self._last_refresh) < self.unknown_kid_cooldown:
                return
        with self._refresh_lock:
            now = time.time()
            with self._lock:
                if self._last_refresh and (now - self._last_refresh) < self.unknown_kid_cooldown:
                    return
            try:
                self.refresh()
            except Exception:
                with self._lock:
                    self._last_refresh = time.time()

    def verify(self, token: str, host: str, scope: str = "", now_unix: Optional[int] = None) -> VerifyResult:
        now = int(time.time()) if now_unix is None else int(now_unix)
        norm_host = normalize_host(host)
        if not norm_host:
            return VerifyResult(valid=False, code=CODE_INVALID_HOST, server_time=now)
        if scope and scope not in VALID_SCOPES:
            return VerifyResult(valid=False, code=CODE_INVALID_SCOPE, host=norm_host, server_time=now)

        ck = (token, norm_host, scope)
        with self._lock:
            cached = self._valid_cache.get(ck)
            if cached is not None:
                if now >= cached.expires_at or cached.kid in self._revoked or cached.kid not in self._keys:
                    self._valid_cache.pop(ck, None)
                elif now >= cached.issued_at - CLOCK_SKEW_SEC:
                    return VerifyResult(
                        valid=True,
                        code=CODE_OK,
                        issuer=cached.issuer,
                        host=cached.host,
                        scope=cached.scope,
                        kid=cached.kid,
                        issued_at=cached.issued_at,
                        expires_at=cached.expires_at,
                        ttl_seconds=max(0, cached.expires_at - now),
                        server_time=now,
                    )

        parsed = parse_compact_jwt(token)
        if parsed is None:
            return VerifyResult(valid=False, code=CODE_INVALID_TOKEN, host=norm_host, server_time=now)
        hdr, cl, signing_input, sig = parsed

        if hdr.get("alg") != ALG_EDDSA:
            return VerifyResult(valid=False, code=CODE_INVALID_TOKEN, host=norm_host, server_time=now)
        kid = str(hdr.get("kid") or "")
        if not kid:
            return VerifyResult(valid=False, code=CODE_INVALID_TOKEN, host=norm_host, server_time=now)

        with self._lock:
            revoked = kid in self._revoked
            pub = self._keys.get(kid)
        if revoked:
            return VerifyResult(valid=False, code=CODE_REVOKED, host=norm_host, server_time=now)
        if pub is None:
            self._refresh_if_cooled_down()
            with self._lock:
                revoked = kid in self._revoked
                pub = self._keys.get(kid)
            if revoked:
                return VerifyResult(valid=False, code=CODE_REVOKED, host=norm_host, server_time=now)
            if pub is None:
                return VerifyResult(valid=False, code=CODE_INVALID_TOKEN, host=norm_host, server_time=now)

        iss = cl.get("iss")
        scp = cl.get("scp")
        aud = cl.get("aud")
        iat = cl.get("iat")
        exp = cl.get("exp")
        if (
            iss != ISSUER
            or scp not in VALID_SCOPES
            or not isinstance(iat, int)
            or not isinstance(exp, int)
            or iat <= 0
            or exp <= iat
        ):
            return VerifyResult(valid=False, code=CODE_INVALID_TOKEN, host=norm_host, server_time=now)
        if now < iat - CLOCK_SKEW_SEC:
            return VerifyResult(valid=False, code=CODE_INVALID_TOKEN, host=norm_host, server_time=now)
        if now >= exp:
            return VerifyResult(valid=False, code=CODE_EXPIRED, host=norm_host, server_time=now)
        if aud != norm_host:
            return VerifyResult(valid=False, code=CODE_HOST_MISMATCH, host=norm_host, server_time=now)
        if scope and scp != scope:
            return VerifyResult(valid=False, code=CODE_SCOPE_MISMATCH, host=norm_host, server_time=now)

        try:
            pub.verify(sig, signing_input)
        except InvalidSignature:
            return VerifyResult(valid=False, code=CODE_INVALID_TOKEN, host=norm_host, server_time=now)

        res = VerifyResult(
            valid=True,
            code=CODE_OK,
            issuer=ISSUER,
            host=norm_host,
            scope=scp,
            kid=kid,
            issued_at=iat,
            expires_at=exp,
            ttl_seconds=max(0, exp - now),
            server_time=now,
        )
        with self._lock:
            if len(self._valid_cache) >= 4096:
                self._valid_cache.clear()
            self._valid_cache[ck] = res
        return res
