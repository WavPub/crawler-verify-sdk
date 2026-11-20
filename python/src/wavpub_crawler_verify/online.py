from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Dict, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

from .common import (
    CODE_CIRCUIT_OPEN,
    CODE_INVALID_HOST,
    CODE_INVALID_SCOPE,
    CODE_INVALID_TOKEN,
    CODE_RATE_LIMITED,
    CODE_SERVICE_UNAVAILABLE,
    DEFAULT_VERIFY_URL,
    VALID_SCOPES,
    VerifyResult,
    looks_like_jwt,
    normalize_host,
)


class OnlineVerifier:
    """在线调用 GET /api/request-verify 的核验器（内置正负缓存、单 IP 失败熔断、500ms Fail-Normal）。"""

    def __init__(
        self,
        verify_url: str = DEFAULT_VERIFY_URL,
        timeout: float = 0.5,
    ) -> None:
        self.verify_url = verify_url
        self.timeout = timeout
        self._lock = threading.Lock()
        self._cache: Dict[str, Tuple[VerifyResult, float]] = {}
        self._ip_fails: Dict[str, Tuple[int, float, float]] = {}

    def verify(
        self,
        token: str,
        host: str,
        scope: str = "",
        client_ip: str = "",
    ) -> VerifyResult:
        now = time.time()
        now_unix = int(now)

        norm_host = normalize_host(host)
        if not norm_host:
            return VerifyResult(valid=False, code=CODE_INVALID_HOST, server_time=now_unix)
        if scope and scope not in VALID_SCOPES:
            return VerifyResult(valid=False, code=CODE_INVALID_SCOPE, host=norm_host, server_time=now_unix)
        if not looks_like_jwt(token):
            self._record_ip_fail(client_ip, now)
            return VerifyResult(valid=False, code=CODE_INVALID_TOKEN, host=norm_host, server_time=now_unix)
        if self._is_ip_blocked(client_ip, now):
            return VerifyResult(valid=False, code=CODE_CIRCUIT_OPEN, host=norm_host, server_time=now_unix)

        ck = hashlib.sha256(f"{token}\x00{norm_host}\x00{scope}".encode("utf-8")).hexdigest()[:32]
        with self._lock:
            entry = self._cache.get(ck)
            if entry is not None:
                cached, exp_at = entry
                if now < exp_at:
                    return cached
                self._cache.pop(ck, None)

        params = {"token": token, "host": norm_host}
        if scope:
            params["scope"] = scope
        sep = "&" if "?" in self.verify_url else "?"
        url = f"{self.verify_url}{sep}{urllib.parse.urlencode(params)}"

        req = urllib.request.Request(url, method="GET")
        status = 0
        raw_body = b""
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                raw_body = resp.read(16 << 10)
        except urllib.error.HTTPError as e:
            status = e.code
            raw_body = e.read(16 << 10)
        except Exception:
            return VerifyResult(
                valid=False, code=CODE_SERVICE_UNAVAILABLE, host=norm_host, server_time=now_unix, degraded=True
            )

        data: dict = {}
        try:
            data = json.loads(raw_body.decode("utf-8"))
        except Exception:
            pass

        resp_host = str(data.get("host") or norm_host)
        if status == 200 and data.get("valid") is True and resp_host == norm_host:
            ttl = int(data.get("ttl_seconds") or 0)
            res = VerifyResult(
                valid=True,
                code=str(data.get("code") or "ok"),
                issuer=str(data.get("issuer") or "wav.pub"),
                host=resp_host,
                scope=str(data.get("scope") or ""),
                kid=str(data.get("kid") or ""),
                issued_at=int(data.get("issued_at") or 0),
                expires_at=int(data.get("expires_at") or 0),
                ttl_seconds=ttl,
                server_time=int(data.get("server_time") or now_unix),
            )
            cache_ttl = min(max(0, ttl - 5), 300)
            if cache_ttl > 0:
                self._put_cache(ck, res, now + cache_ttl)
            return res

        if status in (400, 403):
            res = VerifyResult(
                valid=False,
                code=str(data.get("code") or CODE_INVALID_TOKEN),
                host=resp_host,
                server_time=int(data.get("server_time") or now_unix),
            )
            self._put_cache(ck, res, now + 60.0)
            self._record_ip_fail(client_ip, now)
            return res

        return VerifyResult(
            valid=False,
            code=str(data.get("code") or (CODE_RATE_LIMITED if status == 429 else CODE_SERVICE_UNAVAILABLE)),
            host=resp_host,
            server_time=now_unix,
            degraded=True,
        )

    def _put_cache(self, ck: str, res: VerifyResult, exp_at: float) -> None:
        with self._lock:
            if len(self._cache) >= 8192:
                self._cache.clear()
            self._cache[ck] = (res, exp_at)

    def _is_ip_blocked(self, ip: str, now: float) -> bool:
        if not ip:
            return False
        with self._lock:
            st = self._ip_fails.get(ip)
            return st is not None and now < st[2]

    def _record_ip_fail(self, ip: str, now: float) -> None:
        if not ip:
            return
        with self._lock:
            if len(self._ip_fails) >= 8192:
                self._ip_fails.clear()
            st = self._ip_fails.get(ip)
            if st is None or now > st[1]:
                self._ip_fails[ip] = (1, now + 60.0, 0.0)
                return
            cnt = st[0] + 1
            blocked_until = now + 600.0 if cnt >= 3 else st[2]
            self._ip_fails[ip] = (cnt, st[1], blocked_until)
