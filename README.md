# WavPub Crawler Verify SDK（声湃抓取器身份验证官方 SDK）

[![CI](https://github.com/WavPub/crawler-verify-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/WavPub/crawler-verify-sdk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

面向播客内容托管平台与 WAF/CDN（如小宇宙、喜马拉雅、荔枝等）的官方多语言核验 SDK，用于快速、零误杀地识别来自 **声湃（WavPub）** 的 RSS、封面与音频抓取请求，避免误风控拦截。

- **在线中文接入指南**：https://wav.pub/crawler
- **0 RTT 公钥目录（JWKS）**：`https://wav.pub/.well-known/wavpub-crawler-jwks.json`
- **在线回调验证接口**：`https://wav.pub/api/request-verify`

---

## 两种核验方式对比

声湃的每次外呼请求均携带：
- `User-Agent`：`WavPub/1.0 (+https://wav.pub/crawler)`（RSS/封面）或 `WavPub-Audio/1.0 (+https://wav.pub/crawler)`（音频下载）
- `X-WavPub-Token`：标准确定性 **EdDSA JWT**（RFC 7519 + RFC 8037），`aud` 绑定目标域名，按 5 分钟窗口复用、10 分钟过期
- `X-WavPub-Trace-ID`：单次请求追踪 ID（`wpt_…`），不参与验签，用于双方日志关联排障

| 核验方式 | 推荐度 | 单次延迟 | 网络耦合 | 核心特性 |
|---|---|---|---|---|
| **方式一：`OfflineVerifier`（0 RTT 离线验签）** | ⭐⭐⭐⭐⭐ 强烈推荐 | **0 ms**（~50μs 本地 Ed25519） | 零耦合 | 后台定时 `ETag`（304 零带宽）刷新 JWKS + 未知 `kid` 60 秒冷却单飞防刷 + `revoked_kids` 自动剔除 + 锁定 `alg=EdDSA` |
| **方式二：`OnlineVerifier`（在线回调接口）** | ⭐⭐⭐ 快速联调 | 首次 ~20-100ms，命中缓存 0ms | 弱耦合（Fail-Normal） | 内置正则快筛 + 正负 LRU 缓存 + `singleflight` 合并 + **单 IP 失败熔断（防反射 DDoS）** + 500ms 超时降级 |

---

## 支持语言与目录结构

```text
crawler-verify-sdk/
├── spec/
│   ├── protocol.md          # 完整协议规范（JWT、JWKS、错误码、密钥轮换与安全边界）
│   └── vectors.json         # 三语言共用测试向量（与声湃服务端字节级对齐）
├── go/                      # Go 1.22+（纯标准库，0 第三方依赖）+ net/http、Gin 示例
├── java/                    # Java 17+（原生 JCA Ed25519 + HttpClient）+ Servlet/Spring Boot 示例
└── python/                  # Python 3.9+（仅依赖 cryptography）+ FastAPI、Flask 示例
```

---

## 快速开始

### Go（零第三方依赖）

```bash
go get github.com/WavPub/crawler-verify-sdk/go
```

```go
// 方式一：0 RTT 本地离线验签（推荐）
v, err := wavpubverify.NewOfflineVerifier(ctx)
defer v.Close()

res := v.Verify(r.Header.Get("X-WavPub-Token"), r.Host, "rss")
if res.Valid {
    // 确认为声湃抓取请求
}

// 方式二：在线 HTTP 验证
ov := wavpubverify.NewOnlineVerifier()
res := ov.Verify(r.Context(), r.Header.Get("X-WavPub-Token"), r.Host, "rss", clientIP)
```

详见 [go/README.md](go/README.md) 与 [go/examples/](go/examples/)。

### Java（JDK 17+）

```java
// 方式一：0 RTT 本地离线验签（推荐）
try (OfflineVerifier verifier = OfflineVerifier.builder().build()) {
    VerifyResult res = verifier.verify(
        request.getHeader("X-WavPub-Token"),
        request.getServerName(),
        "rss"
    );
    if (res.isValid()) {
        // 确认为声湃抓取请求
    }
}
```

详见 [java/README.md](java/README.md) 与 [java/examples/](java/examples/)。

### Python（3.9+）

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

---

## 密钥轮换保障

声湃实行 OIDC 标准三阶段密钥轮换：
1. **预公布（≥ 24 小时）**：新公钥先以 `status="next"` 加入 JWKS，声湃仍只用旧密钥签发；
2. **无感切流（≥ 1 小时）**：切到新密钥签发，旧公钥以 `status="previous"` 保留覆盖在途令牌；
3. **安全下线 / 应急吊销**：下线后移出旧公钥；极端泄露时写入 `revoked_kids` 并立即刷新 CDN 边缘缓存。

所有官方 SDK 均已内置 `ETag` 异步轮询（默认 5 分钟）、全量替换公钥表、`revoked_kids` 清理以及未知 `kid` 60 秒冷却单飞刷新，接入方无需人工干预。
