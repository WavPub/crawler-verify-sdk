# WavPub Crawler Verify SDK — Java

面向 JDK 17+，直接使用标准库原生 `Ed25519` JCA 与 `java.net.http.HttpClient`，仅依赖 `jackson-databind`。

## 快速开始

```java
// 方式一（推荐）：0 RTT 本地离线验签
OfflineVerifier offline = OfflineVerifier.builder().build();
VerifyResult res = offline.verify(
    request.getHeader(OfflineVerifier.HEADER_TOKEN),
    request.getServerName(),
    "rss"
);
if (res.isValid()) {
    // 确认为声湃抓取请求
}

// 方式二：在线 HTTP 接口验证
OnlineVerifier online = OnlineVerifier.builder().build();
VerifyResult onlineRes = online.verify(
    request.getHeader(OfflineVerifier.HEADER_TOKEN),
    request.getServerName(),
    "rss",
    clientIp
);
```

Spring Boot / Servlet Filter 接入示例见 [examples/SpringBootFilterExample.java](examples/SpringBootFilterExample.java)。
