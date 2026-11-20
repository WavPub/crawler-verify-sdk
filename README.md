# WavPub Crawler Verify SDK · 声湃抓取器身份验证官方 SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **中文** | **[English](#english-documentation)**

---

## 中文文档

面向播客内容托管平台、CDN 与 WAF（如小宇宙、喜马拉雅、荔枝等）的官方多语言核验 SDK，用于快速、零误杀地识别来自 **声湃（WavPub）** 的 RSS、封面与音频抓取请求，避免误风控拦截。

- **在线双语接入指南**：https://wav.pub/crawler
- **0 RTT 公钥目录（JWKS）**：`https://wav.pub/.well-known/wavpub-crawler-jwks.json`
- **在线回调验证接口**：`https://wav.pub/api/request-verify`

### 两种核验方式对比

声湃的每次对外抓取请求均携带：
- `User-Agent`：`WavPub/1.0 (+https://wav.pub/crawler)`（RSS / 封面）或 `WavPub-Audio/1.0 (+https://wav.pub/crawler)`（音频下载）
- `X-WavPub-Token`：标准确定性 **EdDSA JWT**（RFC 7519 + RFC 8037），`aud` 绑定归一化目标域名，按 5 分钟窗口复用、10 分钟过期
- `X-WavPub-Trace-ID`：单次请求追踪 ID（`wpt_<24位小写hex>`），不参与验签，用于双方日志关联排障

| 核验方式 | 推荐度 | 单次延迟 | 网络耦合 | 核心特性 |
|---|---|---|---|---|
| **方式一：`OfflineVerifier`（0 RTT 离线验签）** | ⭐⭐⭐⭐⭐ 强烈推荐 | **0 ms**（~50μs 本地 Ed25519） | 零耦合 | 后台定时 `ETag`（304 零带宽）刷新 JWKS + 未知 `kid` 60 秒冷却单飞防刷 + `revoked_kids` 自动剔除 + 锁定 `alg=EdDSA` |
| **方式二：`OnlineVerifier`（在线回调接口）** | ⭐⭐⭐ 快速联调 | 首次 ~20–100ms，命中缓存 0ms | 弱耦合（Fail-Normal） | 内置格式快筛 + 正负 LRU 缓存 + `singleflight` 合并 + **单 IP 失败熔断（防反射 DDoS）** + 500ms 超时降级 |

### 支持语言与目录结构

```text
crawler-verify-sdk/
├── spec/
│   ├── protocol.md          # 完整协议规范（中英双语：JWT、JWKS、错误码、密钥轮换与安全边界）
│   └── vectors.json         # 三语言共用测试向量（与声湃服务端字节级对齐）
├── go/                      # Go 1.22+（纯标准库，0 第三方依赖）+ net/http、Gin 示例
├── java/                    # Java 17+（原生 JCA Ed25519 + HttpClient）+ Servlet/Spring Boot 示例
└── python/                  # Python 3.9+（仅依赖 cryptography）+ FastAPI、Flask 示例
```

### 快速开始

#### Go（零第三方依赖）

```bash
go get github.com/WavPub/crawler-verify-sdk/go
```

```go
// 方式一：0 RTT 本地离线验签（推荐）
v, err := wavpubverify.NewOfflineVerifier(ctx)
defer v.Close()

res := v.Verify(r.Header.Get(wavpubverify.HeaderToken), r.Host, wavpubverify.ScopeRSS)
if res.Valid {
    // 确认为声湃抓取请求
}

// 方式二：在线 HTTP 接口验证
ov := wavpubverify.NewOnlineVerifier()
res = ov.Verify(r.Context(), r.Header.Get(wavpubverify.HeaderToken), r.Host, wavpubverify.ScopeRSS, clientIP)
```

详见 [go/README.md](go/README.md) 与 [go/examples/](go/examples/)。

#### Java（JDK 17+）

```java
// 方式一：0 RTT 本地离线验签（推荐）
try (OfflineVerifier verifier = OfflineVerifier.builder().build()) {
    VerifyResult res = verifier.verify(
        request.getHeader(OfflineVerifier.HEADER_TOKEN),
        request.getServerName(),
        "rss"
    );
    if (res.isValid()) {
        // 确认为声湃抓取请求
    }
}
```

详见 [java/README.md](java/README.md) 与 [java/examples/](java/examples/)。

#### Python（3.9+）

```bash
pip install "git+https://github.com/WavPub/crawler-verify-sdk.git#subdirectory=python"
```

```python
from wavpub_crawler_verify import OfflineVerifier

verifier = OfflineVerifier()
res = verifier.verify(
    token=request.headers.get("X-WavPub-Token", ""),
    host=request.headers.get("Host", ""),
    scope="rss",
)
if res.valid:
    ...
```

详见 [python/README.md](python/README.md) 与 [python/examples/](python/examples/)。

### 三阶段无感密钥轮换

1. **预公布（≥ 24 小时）**：新公钥先以 `status="next"` 加入 JWKS，声湃仍只用旧 Active 签发；
2. **切流晋升（≥ 1 小时）**：切到新密钥签发，旧公钥以 `status="previous"` 保留覆盖在途旧令牌；
3. **安全下线 / 应急吊销**：宽限期满移出旧公钥；极端泄露时写入 `revoked_kids` 并立即刷新 CDN 边缘缓存。

所有官方 SDK 均内置 `ETag` 异步轮询（默认 5 分钟）、全量替换公钥表、`revoked_kids` 自动剔除与未知 `kid` 冷却刷新，接入方无需人工干预。

---

## English Documentation

Official multi-language verification SDKs for podcast hosting platforms, CDNs, and WAFs to reliably identify **WavPub** RSS, cover artwork, and episode audio crawlers without false-positive rate limiting or bot challenges.

- **Bilingual Integration Guide**: https://wav.pub/crawler#en
- **0-RTT Public Key Directory (JWKS)**: `https://wav.pub/.well-known/wavpub-crawler-jwks.json`
- **Online Verification Endpoint**: `https://wav.pub/api/request-verify`

### Verification Modes Comparison

Every outbound WavPub request carries:
- `User-Agent`: `WavPub/1.0 (+https://wav.pub/crawler)` (RSS & artwork) or `WavPub-Audio/1.0 (+https://wav.pub/crawler)` (audio download)
- `X-WavPub-Token`: Deterministic **EdDSA JWT** (RFC 7519 + RFC 8037) with `aud` bound to the normalized target host, reused within 5-minute buckets and valid for 10 minutes
- `X-WavPub-Trace-ID`: Per-request trace ID (`wpt_<24 lowercase hex>`) for cross-system log correlation (excluded from signature cache keys)

| Mode | Recommendation | Latency | Network Coupling | Highlights |
|---|---|---|---|---|
| **Mode 1: `OfflineVerifier` (0-RTT Offline)** | ⭐⭐⭐⭐⭐ Recommended | **0 ms** (~50μs local Ed25519) | Zero runtime coupling | Background `ETag`/304 JWKS sync, unknown-`kid` 60s cooldown singleflight refresh, automatic `revoked_kids` enforcement, strict `alg=EdDSA` lock |
| **Mode 2: `OnlineVerifier` (Online API)** | ⭐⭐⭐ Quick Pilot | ~20–100ms cold, 0ms cached | Loose (Fail-Normal) | Format pre-filter, positive/negative LRU cache, singleflight deduplication, per-IP failure circuit breaker, 500ms timeout degradation |

### Supported Languages & Repository Layout

```text
crawler-verify-sdk/
├── spec/
│   ├── protocol.md          # Bilingual protocol specification (JWT, JWKS, error codes, rotation, security)
│   └── vectors.json         # Shared cross-language conformance test vectors
├── go/                      # Go 1.22+ (zero external dependencies) + net/http & Gin examples
├── java/                    # Java 17+ (native JCA Ed25519 + HttpClient) + Servlet/Spring Boot example
└── python/                  # Python 3.9+ (cryptography only) + FastAPI & Flask examples
```

### Quick Start

#### Go (Zero External Dependencies)

```bash
go get github.com/WavPub/crawler-verify-sdk/go
```

```go
// Mode 1: 0-RTT local offline verification (recommended)
v, err := wavpubverify.NewOfflineVerifier(ctx)
defer v.Close()

res := v.Verify(r.Header.Get(wavpubverify.HeaderToken), r.Host, wavpubverify.ScopeRSS)
if res.Valid {
    // Verified WavPub crawler request
}

// Mode 2: Online HTTP callback verification
ov := wavpubverify.NewOnlineVerifier()
res = ov.Verify(r.Context(), r.Header.Get(wavpubverify.HeaderToken), r.Host, wavpubverify.ScopeRSS, clientIP)
```

See [go/README.md](go/README.md) and [go/examples/](go/examples/).

#### Java (JDK 17+)

```java
// Mode 1: 0-RTT local offline verification (recommended)
try (OfflineVerifier verifier = OfflineVerifier.builder().build()) {
    VerifyResult res = verifier.verify(
        request.getHeader(OfflineVerifier.HEADER_TOKEN),
        request.getServerName(),
        "rss"
    );
    if (res.isValid()) {
        // Verified WavPub crawler request
    }
}
```

See [java/README.md](java/README.md) and [java/examples/](java/examples/).

#### Python (3.9+)

```bash
pip install "git+https://github.com/WavPub/crawler-verify-sdk.git#subdirectory=python"
```

```python
from wavpub_crawler_verify import OfflineVerifier

verifier = OfflineVerifier()
res = verifier.verify(
    token=request.headers.get("X-WavPub-Token", ""),
    host=request.headers.get("Host", ""),
    scope="rss",
)
if res.valid:
    ...
```

See [python/README.md](python/README.md) and [python/examples/](python/examples/).

### Zero-Downtime Three-Phase Key Rotation

1. **Prepare Next (≥ 24 hours)**: The new public key is published in JWKS with `status="next"` while WavPub continues signing with Active.
2. **Promote (≥ 1 hour)**: Next becomes Active and the old Active moves to `status="previous"` so in-flight tokens (≤ 10 min lifetime) keep verifying seamlessly.
3. **Retire / Emergency Revoke**: Previous is removed after the grace period; on key compromise, the `kid` is immediately added to `revoked_kids` and purged at the CDN edge.

All official SDKs handle background `ETag`/304 polling (default 5 minutes), full key-set replacement, `revoked_kids` rejection, and debounced unknown-`kid` refreshes automatically with zero manual coordination.
