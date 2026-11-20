package wavpubverify

import (
	"context"
	"net/http"
)

type ctxKey struct{}

// ResultFromContext 从中间件注入的 Context 中取出核验结果。
func ResultFromContext(ctx context.Context) (VerifyResult, bool) {
	res, ok := ctx.Value(ctxKey{}).(VerifyResult)
	return res, ok
}

// OfflineMiddleware 标准 net/http 中间件：仅在请求携带 X-WavPub-Token 时执行 0 RTT 本地验签，
// 并将 VerifyResult 存入 r.Context()，后续风控层可通过 ResultFromContext 读取。
func OfflineMiddleware(v *OfflineVerifier, scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tok := r.Header.Get(HeaderToken); tok != "" && v != nil {
				res := v.Verify(tok, r.Host, scope)
				r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, res))
			}
			next.ServeHTTP(w, r)
		})
	}
}
