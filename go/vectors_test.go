package wavpubverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type vectorFile struct {
	JWKS  json.RawMessage `json:"jwks"`
	Cases []struct {
		Name      string `json:"name"`
		Token     string `json:"token"`
		Host      string `json:"host"`
		Scope     string `json:"scope"`
		NowUnix   int64  `json:"now_unix"`
		WantValid bool   `json:"want_valid"`
		WantCode  string `json:"want_code"`
		WantHost  string `json:"want_host"`
		WantScope string `json:"want_scope"`
		WantKid   string `json:"want_kid"`
	} `json:"cases"`
}

func TestSharedVectors_OfflineVerifier(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "spec", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("unmarshal vectors.json: %v", err)
	}

	v, err := NewOfflineVerifierFromJWKS(vf.JWKS)
	if err != nil {
		t.Fatalf("NewOfflineVerifierFromJWKS: %v", err)
	}

	for _, tc := range vf.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := v.VerifyAt(time.Unix(tc.NowUnix, 0).UTC(), tc.Token, tc.Host, tc.Scope)
			if got.Valid != tc.WantValid || got.Code != tc.WantCode || got.Host != tc.WantHost {
				t.Fatalf("got=%+v, want valid=%v code=%q host=%q", got, tc.WantValid, tc.WantCode, tc.WantHost)
			}
			if tc.WantScope != "" && got.Scope != tc.WantScope {
				t.Errorf("scope=%q, want %q", got.Scope, tc.WantScope)
			}
			if tc.WantKid != "" && got.Kid != tc.WantKid {
				t.Errorf("kid=%q, want %q", got.Kid, tc.WantKid)
			}
		})
	}
}

func TestOfflineVerifier_UnknownKidCooldownAndETag304(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("..", "spec", "vectors.json"))
	var vf vectorFile
	_ = json.Unmarshal(raw, &vf)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("ETag", `"rev-1"`)
		if r.Header.Get("If-None-Match") == `"rev-1"` && n > 1 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(vf.JWKS)
	}))
	defer srv.Close()

	v, err := NewOfflineVerifier(context.Background(),
		WithJWKSURL(srv.URL),
		WithUnknownKidCooldown(time.Minute),
		WithPollInterval(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewOfflineVerifier: %v", err)
	}
	defer v.Close()

	if err := v.Refresh(context.Background()); err != nil {
		t.Fatalf("304 Refresh failed: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d, want 2", hits.Load())
	}
}

func TestOnlineVerifier_CacheAndIPCircuitBreaker(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("..", "spec", "vectors.json"))
	var vf vectorFile
	_ = json.Unmarshal(raw, &vf)
	validCase := vf.Cases[0]

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("token") == validCase.Token && r.URL.Query().Get("host") == "feed.xyzcdn.net" {
			_ = json.NewEncoder(w).Encode(VerifyResult{
				Valid: true, Code: CodeOK, Host: "feed.xyzcdn.net", Scope: "rss",
				ExpiresAt: time.Now().Add(5 * time.Minute).Unix(), TTLSeconds: 300,
			})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(VerifyResult{Valid: false, Code: CodeInvalidToken, Host: r.URL.Query().Get("host")})
	}))
	defer srv.Close()

	ov := NewOnlineVerifier(WithVerifyURL(srv.URL))

	// 连续两次相同合法请求 → 第二次命中正向缓存，只回调 1 次
	r1 := ov.Verify(context.Background(), validCase.Token, "FEED.XYZCDN.NET", "rss", "1.2.3.4")
	r2 := ov.Verify(context.Background(), validCase.Token, "feed.xyzcdn.net", "rss", "1.2.3.4")
	if !r1.Valid || !r2.Valid || calls.Load() != 1 {
		t.Fatalf("cache miss: r1=%+v r2=%+v calls=%d", r1, r2, calls.Load())
	}

	// 同一攻击 IP 连续发 3 次不同无效令牌 → 第 4 次触发本地熔断不再回源
	for range 3 {
		_ = ov.Verify(context.Background(), "not.a.jwt", "feed.xyzcdn.net", "rss", "9.9.9.9")
	}
	before := calls.Load()
	blocked := ov.Verify(context.Background(), validCase.Token, "feed.xyzcdn.net", "rss", "9.9.9.9")
	if blocked.Valid || blocked.Code != CodeCircuitOpen || calls.Load() != before {
		t.Fatalf("期望单 IP 熔断，实得 %+v calls=%d", blocked, calls.Load())
	}
}
