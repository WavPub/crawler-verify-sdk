# WavPub Crawler Identity Verification Protocol (v1) · 声湃抓取器身份验证协议规范

> **中文规范** | **[English Specification](#english-specification)**

---

## 中文规范

### 1. 请求头

| 请求头 | 说明 |
|---|---|
| `User-Agent` | RSS / 封面：`WavPub/1.0 (+https://wav.pub/crawler)`；音频下载：`WavPub-Audio/1.0 (+https://wav.pub/crawler)` |
| `X-WavPub-Token` | 标准 Compact JWS（RFC 7519 + RFC 8037），算法固定为 `EdDSA`（Ed25519） |
| `X-WavPub-Trace-ID` | 单次请求追踪号（`wpt_<24位小写hex>`），不参与验签，仅用于双方日志排障 |

### 2. JWT 结构与强制校验清单

- **Header**：`{"alg":"EdDSA","typ":"JWT","kid":"<string>"}`
- **Payload**：`{"iss":"wav.pub","aud":"<normalized_host>","scp":"rss|cover|audio","iat":<unix>,"exp":<unix>}`

校验步骤（缺一不可）：
1. 令牌总长 ≤ 512 字节，严格三段 Base64URL（无填充），签名段解码后必须为 64 字节。
2. Header `alg` 必须严格等于 `"EdDSA"`（防范 `none` / `HS256` 算法混淆攻击）；`kid` 不能为空。
3. 若 `kid` 在 JWKS 的 `revoked_kids` 中 → 拒绝（`code = "revoked"`）。
4. 按 `kid` 在本地公钥表查找对应 Ed25519 公钥；未找到 → 触发受 60 秒冷却保护的 `singleflight` 刷新，再查一次。
5. `iss` 必须等于 `"wav.pub"`；`scp` 必须是 `rss` / `cover` / `audio` 之一。
6. 时钟窗口：`iat - 30 <= now < exp`（`iat` 允许 30 秒时钟偏移；`now >= exp` 返回 `code = "expired"`）。
7. `aud` 必须严格等于 `normalize_host(request_host)`（去端口/方括号 → 去末尾点号 → IDNA ASCII → 小写）；不匹配返回 `code = "host_mismatch"`。
8. 若调用方指定期望 `scope`，`scp` 必须一致（否则 `code = "scope_mismatch"`）。
9. 使用公钥验证 `Ed25519.Verify(pub, ascii(header_b64 + "." + payload_b64), sig)`。

### 3. 公钥目录（JWKS）

- 地址：`GET https://wav.pub/.well-known/wavpub-crawler-jwks.json`
- 响应头：`Cache-Control: public, max-age=60, s-maxage=60, stale-while-revalidate=3600`、`ETag: "sha256-..."`
- 支持 `If-None-Match` → `304 Not Modified`。
- 刷新策略：后台每 5–15 分钟（最长不超过 1 小时）异步轮询；拿到 `200` 后**全量替换**本地公钥表与 `revoked_kids`。

### 4. 在线验证接口

- 地址：`GET https://wav.pub/api/request-verify?token=<X-WavPub-Token>&host=<Host>[&scope=rss|cover|audio]`
- 亦支持经请求头 `X-WavPub-Token` 传递令牌；`host` 为必填参数。
- 响应头：`Cache-Control: no-store`。
- 状态码：`200`（`valid: true`）、`403`（`valid: false`，JSON 恒带回归一化 `host`）、`400`（缺参/非法）、`429`（防刷限流）、`503`（服务降级，上游应 Fail-Normal）。

### 5. 301/302 重定向语义

- **RSS / 封面**：跨域名重定向时剥离旧令牌并按新 Host 重新签名，`X-WavPub-Trace-ID` 保持一致。
- **音频下载**：以首跳音频地址的 Host 预签 `scp="audio"` 令牌，遇到 301/302 不再回调重新签名。

---

## English Specification

### 1. HTTP Headers

| Header | Description |
|---|---|
| `User-Agent` | RSS / Cover: `WavPub/1.0 (+https://wav.pub/crawler)`; Audio download: `WavPub-Audio/1.0 (+https://wav.pub/crawler)` |
| `X-WavPub-Token` | Standard Compact JWS (RFC 7519 + RFC 8037) using `EdDSA` (Ed25519) exclusively |
| `X-WavPub-Trace-ID` | Per-request trace identifier (`wpt_<24 lowercase hex>`), not part of signature verification, used for log correlation |

### 2. JWT Structure & Mandatory Verification Checklist

- **Header**: `{"alg":"EdDSA","typ":"JWT","kid":"<string>"}`
- **Payload**: `{"iss":"wav.pub","aud":"<normalized_host>","scp":"rss|cover|audio","iat":<unix>,"exp":<unix>}`

Required checks (all mandatory):
1. Total token length ≤ 512 bytes, exactly 3 unpadded Base64URL segments, signature decodes to exactly 64 bytes.
2. Header `alg` MUST equal `"EdDSA"` (reject `none`, `HS256`, `RS256`, etc.); `kid` MUST be non-empty.
3. If `kid` appears in JWKS `revoked_kids`, reject immediately with `code = "revoked"`.
4. Look up the Ed25519 public key by `kid`. If missing, trigger a singleflight JWKS refresh protected by a 60-second cooldown and retry lookup once.
5. `iss` MUST equal `"wav.pub"`; `scp` MUST be one of `rss`, `cover`, or `audio`.
6. Time bounds: `iat - 30 <= now < exp` (30s clock skew tolerance on `iat`; `now >= exp` returns `code = "expired"`).
7. `aud` MUST strictly equal `normalize_host(request_host)` (strip port/brackets → strip trailing dot → IDNA ASCII → lowercase); otherwise return `code = "host_mismatch"`.
8. If the caller specifies an expected `scope`, `scp` MUST match (otherwise `code = "scope_mismatch"`).
9. Verify `Ed25519.Verify(pub, ascii(header_b64 + "." + payload_b64), sig)`.

### 3. Public Key Directory (JWKS)

- URL: `GET https://wav.pub/.well-known/wavpub-crawler-jwks.json`
- Headers: `Cache-Control: public, max-age=60, s-maxage=60, stale-while-revalidate=3600`, `ETag: "sha256-..."`
- Supports `If-None-Match` → `304 Not Modified`.
- Sync policy: poll asynchronously every 5–15 minutes (no longer than 1 hour); on `200 OK`, atomically replace the entire local key map and `revoked_kids` set.

### 4. Online Verification Endpoint

- URL: `GET https://wav.pub/api/request-verify?token=<X-WavPub-Token>&host=<Host>[&scope=rss|cover|audio]`
- Also accepts the token via the `X-WavPub-Token` request header; `host` is mandatory.
- Response header: `Cache-Control: no-store`.
- Status codes: `200` (`valid: true`), `403` (`valid: false`, always echoing normalized `host`), `400` (missing/invalid params), `429` (rate limited), `503` (unavailable — callers should Fail-Normal).

### 5. 301/302 Redirect Semantics

- **RSS / Cover**: On cross-host redirects, the prior token is stripped and re-signed for the redirect target host while preserving `X-WavPub-Trace-ID`.
- **Audio downloads**: Pre-signed once for the initial audio URL host (`scp="audio"`) and preserved across 301/302 redirects without calling back to WavPub APIs.
