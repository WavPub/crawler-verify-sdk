from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import json
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

HEADER_TOKEN = "X-WavPub-Token"
HEADER_TRACE_ID = "X-WavPub-Trace-ID"

DEFAULT_JWKS_URL = "https://wav.pub/.well-known/wavpub-crawler-jwks.json"
DEFAULT_VERIFY_URL = "https://wav.pub/api/request-verify"

ISSUER = "wav.pub"
ALG_EDDSA = "EdDSA"
MAX_TOKEN_LEN = 512
CLOCK_SKEW_SEC = 30

SCOPE_RSS = "rss"
SCOPE_COVER = "cover"
SCOPE_AUDIO = "audio"
VALID_SCOPES = {SCOPE_RSS, SCOPE_COVER, SCOPE_AUDIO}

CODE_OK = "ok"
CODE_INVALID_TOKEN = "invalid_token"
CODE_EXPIRED = "expired"
CODE_HOST_MISMATCH = "host_mismatch"
CODE_SCOPE_MISMATCH = "scope_mismatch"
CODE_REVOKED = "revoked"
CODE_INVALID_HOST = "invalid_host"
CODE_INVALID_SCOPE = "invalid_scope"
CODE_RATE_LIMITED = "rate_limited"
CODE_SERVICE_UNAVAILABLE = "service_unavailable"
CODE_CIRCUIT_OPEN = "ip_circuit_open"

_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}$")
_HOST_RE = re.compile(r"^[a-z0-9._-]+$")


@dataclass(frozen=True)
class VerifyResult:
    valid: bool
    code: str
    issuer: str = ""
    host: str = ""
    scope: str = ""
    kid: str = ""
    issued_at: int = 0
    expires_at: int = 0
    ttl_seconds: int = 0
    server_time: int = 0
    degraded: bool = False


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def normalize_host(raw: str) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip()
    if not s or len(s) > 255:
        return None
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in s):
        return None

    host = s
    if "://" in s:
        parsed = urlparse(s)
        if not parsed.hostname:
            return None
        host = parsed.hostname
    else:
        if any(c in s for c in "/?#\\@"):
            return None
        if s.startswith("["):
            end = s.find("]")
            if end <= 1:
                return None
            host = s[1:end]
        elif s.count(":") == 1:
            host, port = s.split(":", 1)
            if not port.isdigit():
                return None

    host = host.rstrip(".")
    if not host:
        return None

    try:
        ip = ipaddress.ip_address(host)
        return str(ip).lower()
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if not host or len(host) > 253 or not _HOST_RE.match(host):
        return None
    return host


def looks_like_jwt(token: str) -> bool:
    return bool(token) and len(token) <= MAX_TOKEN_LEN and bool(_JWT_RE.match(token))


def parse_compact_jwt(token: str) -> Optional[Tuple[dict, dict, bytes, bytes]]:
    if not looks_like_jwt(token):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        hdr = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
        sig = b64url_decode(parts[2])
    except Exception:
        return None
    if not isinstance(hdr, dict) or not isinstance(claims, dict) or len(sig) != 64:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return hdr, claims, signing_input, sig
