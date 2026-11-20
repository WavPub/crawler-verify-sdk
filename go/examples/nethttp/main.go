package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	wavpubverify "github.com/WavPub/crawler-verify-sdk/go"
)

func main() {
	ctx := context.Background()

	// 方式一（推荐）：0 RTT 本地离线验签
	offline, err := wavpubverify.NewOfflineVerifier(ctx)
	if err != nil {
		log.Printf("warning: initial JWKS fetch failed (will retry in background): %v", err)
	}
	defer offline.Close()

	// 方式二：在线 HTTP 回调验证
	online := wavpubverify.NewOnlineVerifier()

	mux := http.NewServeMux()
	mux.Handle("/feed.xml", wavpubverify.OfflineMiddleware(offline, wavpubverify.ScopeRSS)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if res, ok := wavpubverify.ResultFromContext(r.Context()); ok && res.Valid {
				w.Header().Set("X-Verified-Crawler", "wavpub")
				fmt.Fprintf(w, "verified wavpub offline: host=%s scope=%s kid=%s\n", res.Host, res.Scope, res.Kid)
				return
			}
			// 演示在线验证路径
			res := online.Verify(r.Context(), r.Header.Get(wavpubverify.HeaderToken), r.Host, wavpubverify.ScopeRSS, r.RemoteAddr)
			fmt.Fprintf(w, "online result: valid=%v code=%s degraded=%v\n", res.Valid, res.Code, res.Degraded)
		}),
	))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
