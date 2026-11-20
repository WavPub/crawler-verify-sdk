# 声湃（WavPub）抓取器身份验证协议规范（v1）

## 1. 请求头

| 请求头 | 说明 |
|---|---|
| `User-Agent` | RSS / 封面：`WavPub/1.0 (+https://wav.pub/crawler)`；音频下载：`WavPub-Audio/1.0 (+https://wav.pub/crawler)` |
| `X-WavPub-Token` | 标准 Compact JWS（RFC 7519 + RFC 8037），算法固定为 `EdDSA`（Ed25519） |
| `X-WavPub-Trace-ID` | 单次请求追踪号（`wpt_<24位小写hex>`），不参与验签，仅用于双方日志排障 |

## 2. JWT 结构与校验规则

- **Header**：`{"alg":"EdDSA","typ":"JWT","kid":"<string>"}`
- **Payload**：`{"iss":"wav.pub","aud":"<normalized_host>","scp":"rss|cover|audio","iat":<unix>,"exp":<unix>}`

### 强制校验清单（缺一不可）
1. 令牌总长 ≤ 512 字节，严格三段 Base64URL（无填充），签名段解码后必须为 64 字节。
2. Header `alg` 必须严格等于 `"EdDSA"`（防范 `none` / `HS256` 算法混淆攻击）；`kid` 不能为空。
3. 若 `kid` 在 JWKS 的 `revoked_kids` 中 → 拒绝（`code = "revoked"`）。
4. 按 `kid` 在本地公钥表查找对应 Ed25519 公钥；未找到 → 触发受 60 秒冷却保护的 `singleflight` 刷新，再查一次。
5. `iss` 必须等于 `"wav.pub"`；`scp` 必须是 `rss` / `cover` / `audio` 之一。
6. 时钟窗口：`iat - 30 <= now < exp`（`iat` 允许 30 秒时钟偏移；`now >= exp` 返回 `code = "expired"`）。
7. `aud` 必须严格等于 `normalize_host(request_host)`（去端口/方括号 → 去末尾点号 → IDNA ASCII → 小写）；不匹配返回 `code = "host_mismatch"`。
8. 若调用方指定期望 `scope`，`scp` 必须一致（否则 `code = "scope_mismatch"`）。
9. 使用公钥验证 `Ed25519.Verify(pub, ascii(header_b64 + "." + payload_b64), sig)`。

## 3. 公钥目录（JWKS）

- 地址：`GET https://wav.pub/.well-known/wavpub-crawler-jwks.json`
- 响应头：`Cache-Control: public, max-age=60, s-maxage=60, stale-while-revalidate=3600`、`ETag: "sha256-..."`
- 支持 `If-None-Match` → `304 Not Modified`。
- 刷新策略：后台每 5–15 分钟（最长不超过 1 小时）异步轮询；拿到 `200` 后**全量替换**本地公钥表与 `revoked_kids`。

## 4. 在线验证接口

- 地址：`GET https://wav.pub/api/request-verify?token=<X-WavPub-Token>&host=<Host>[&scope=rss|cover|audio]`
- 亦支持经请求头 `X-WavPub-Token` 传递令牌；`host` 为必填参数。
- 响应头：`Cache-Control: no-store`。
- 状态码：`200`（`valid: true`）、`403`（`valid: false`，JSON 恒带回归一化 `host`）、`400`（缺参/非法）、`429`（防刷限流）、`503`（服务降级，上游应 Fail-Normal）。
