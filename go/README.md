# WavPub Crawler Verify SDK — Go

纯 Go 标准库实现（**零第三方依赖**），支持 Go 1.22+。

## 安装

```bash
go get github.com/WavPub/crawler-verify-sdk/go
```

## 方式一：0 RTT 本地离线验签（推荐）

```go
v, err := wavpubverify.NewOfflineVerifier(ctx)
if err != nil {
    // 若启动时声湃网络不可达，可继续启动，后台轮询会自动恢复
    log.Printf("initial JWKS sync warning: %v", err)
}
defer v.Close()

res := v.Verify(r.Header.Get(wavpubverify.HeaderToken), r.Host, wavpubverify.ScopeRSS)
if res.Valid {
    // 确认为声湃抓取请求，放行
}
```

## 方式二：在线 HTTP 接口验证

```go
v := wavpubverify.NewOnlineVerifier()
res := v.Verify(r.Context(), r.Header.Get(wavpubverify.HeaderToken), r.Host, wavpubverify.ScopeRSS, clientIP)
if res.Valid {
    // 确认为声湃抓取请求
} else if res.Degraded {
    // 超时或 5xx，Fail-Normal 退回常规风控策略
}
```

更多框架集成示例见 [examples/nethttp](examples/nethttp/main.go) 与 [examples/gin](examples/gin/main.go)。
