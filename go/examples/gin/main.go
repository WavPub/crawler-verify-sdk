// Gin 接入示例片段（复制进你的 Gin 项目中即可运行）
package ginexample

import (
	"net/http"

	wavpubverify "github.com/WavPub/crawler-verify-sdk/go"
)

// GinLikeContext 仅用于无外部依赖展示 Gin 中间件写法，实际项目中直接换成 *gin.Context。
type GinLikeContext interface {
	Request() *http.Request
	ClientIP() string
	Set(key string, value any)
	Next()
}

func WavPubOfflineMiddleware(v *wavpubverify.OfflineVerifier, scope string) func(GinLikeContext) {
	return func(c GinLikeContext) {
		r := c.Request()
		if tok := r.Header.Get(wavpubverify.HeaderToken); tok != "" {
			res := v.Verify(tok, r.Host, scope)
			if res.Valid {
				c.Set("wavpub_verified", true)
				c.Set("wavpub_result", res)
			}
		}
		c.Next()
	}
}
