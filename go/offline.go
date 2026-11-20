package wavpubverify

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type jwksDoc struct {
	Issuer      string   `json:"issuer"`
	Revision    string   `json:"revision"`
	RevokedKids []string `json:"revoked_kids"`
	Keys        []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		X   string `json:"x"`
	} `json:"keys"`
}

// OfflineOption 配置 OfflineVerifier。
type OfflineOption func(*OfflineVerifier)

// WithJWKSURL 自定义 JWKS 地址（默认 https://wav.pub/.well-known/wavpub-crawler-jwks.json）。
func WithJWKSURL(u string) OfflineOption {
	return func(v *OfflineVerifier) {
		if u != "" {
			v.jwksURL = u
		}
	}
}

// WithPollInterval 设置后台 ETag 异步刷新间隔（默认 5 分钟，建议 5~15 分钟，最长不超 1 小时）。
func WithPollInterval(d time.Duration) OfflineOption {
	return func(v *OfflineVerifier) {
		if d >= 10*time.Second {
			v.pollInterval = d
		}
	}
}

// WithUnknownKidCooldown 设置未知 kid 触发主动拉取 JWKS 的全局冷却期（默认 60 秒，防随机 kid 回源风暴）。
func WithUnknownKidCooldown(d time.Duration) OfflineOption {
	return func(v *OfflineVerifier) {
		if d >= 0 {
			v.unknownCooldown = d
		}
	}
}

// WithOfflineHTTPClient 自定义用于拉取 JWKS 的 HTTP 客户端。
func WithOfflineHTTPClient(c *http.Client) OfflineOption {
	return func(v *OfflineVerifier) {
		if c != nil {
			v.httpClient = c
		}
	}
}

// OfflineVerifier 实现 0 RTT 本地 Ed25519 JWKS 离线验签。
type OfflineVerifier struct {
	jwksURL         string
	pollInterval    time.Duration
	unknownCooldown time.Duration
	httpClient      *http.Client
	nowFn           func() time.Time

	mu           sync.RWMutex
	keys         map[string]ed25519.PublicKey
	revoked      map[string]bool
	etag         string
	lastRefresh  time.Time
	validCache   map[string]VerifyResult
	validCacheMu sync.Mutex

	// singleflight 合并未知 kid 刷新
	refreshMu sync.Mutex
	refreshCh chan struct{}

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewOfflineVerifier 创建离线验签器：启动时同步拉取一次 JWKS，并在后台按 pollInterval 定时 ETag 刷新。
// 若首次拉取失败仍返回可用实例与错误，后台轮询会在恢复后自动装入公钥。
func NewOfflineVerifier(ctx context.Context, opts ...OfflineOption) (*OfflineVerifier, error) {
	v := &OfflineVerifier{
		jwksURL:         DefaultJWKSURL,
		pollInterval:    5 * time.Minute,
		unknownCooldown: 60 * time.Second,
		httpClient:      &http.Client{Timeout: 3 * time.Second},
		nowFn:           time.Now,
		keys:            map[string]ed25519.PublicKey{},
		revoked:         map[string]bool{},
		validCache:      map[string]VerifyResult{},
		stopCh:          make(chan struct{}),
	}
	for _, opt := range opts {
		opt(v)
	}
	err := v.Refresh(ctx)
	go v.pollLoop()
	return v, err
}

// NewOfflineVerifierFromJWKS 用静态 JWKS JSON 构造离线验签器（适合单测或外部自管刷新）。
func NewOfflineVerifierFromJWKS(jwksJSON []byte) (*OfflineVerifier, error) {
	v := &OfflineVerifier{
		jwksURL:         "",
		unknownCooldown: 60 * time.Second,
		nowFn:           time.Now,
		keys:            map[string]ed25519.PublicKey{},
		revoked:         map[string]bool{},
		validCache:      map[string]VerifyResult{},
		stopCh:          make(chan struct{}),
	}
	if err := v.LoadJWKS(jwksJSON); err != nil {
		return nil, err
	}
	return v, nil
}

// Close 停止后台 JWKS 轮询协程。
func (v *OfflineVerifier) Close() {
	v.stopOnce.Do(func() { close(v.stopCh) })
}

func (v *OfflineVerifier) pollLoop() {
	if v.jwksURL == "" {
		return
	}
	tk := time.NewTicker(v.pollInterval)
	defer tk.Stop()
	for {
		select {
		case <-v.stopCh:
			return
		case <-tk.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = v.Refresh(ctx)
			cancel()
		}
	}
}

// LoadJWKS 全量替换本地公钥表与吊销列表（同时清空可能关联旧公钥的验签缓存）。
func (v *OfflineVerifier) LoadJWKS(raw []byte) error {
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("wavpubverify: parse JWKS: %w", err)
	}
	revoked := make(map[string]bool, len(doc.RevokedKids))
	for _, k := range doc.RevokedKids {
		if k != "" {
			revoked[k] = true
		}
	}
	keys := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for _, item := range doc.Keys {
		if item.Kty != "OKP" || item.Crv != "Ed25519" || item.Kid == "" || revoked[item.Kid] {
			continue
		}
		pub, err := base64.RawURLEncoding.DecodeString(item.X)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		keys[item.Kid] = ed25519.PublicKey(pub)
	}

	v.mu.Lock()
	v.keys = keys
	v.revoked = revoked
	v.lastRefresh = v.nowFn().UTC()
	v.mu.Unlock()

	v.validCacheMu.Lock()
	clear(v.validCache)
	v.validCacheMu.Unlock()
	return nil
}

// Refresh 立即以 If-None-Match 协商刷新一次 JWKS（304 零带宽不改表，200 全量替换）。
func (v *OfflineVerifier) Refresh(ctx context.Context) error {
	if v.jwksURL == "" {
		return nil
	}
	v.mu.RLock()
	etag := v.etag
	v.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		v.mu.Lock()
		v.lastRefresh = v.nowFn().UTC()
		v.mu.Unlock()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wavpubverify: JWKS HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := v.LoadJWKS(body); err != nil {
		return err
	}
	if newETag := resp.Header.Get("ETag"); newETag != "" {
		v.mu.Lock()
		v.etag = newETag
		v.mu.Unlock()
	}
	return nil
}

// refreshIfCooledDown 对未知 kid 执行「冷却锁 + singleflight 合并」刷新，防止伪造随机 kid 打爆 JWKS。
func (v *OfflineVerifier) refreshIfCooledDown() {
	if v.jwksURL == "" {
		return
	}
	now := v.nowFn().UTC()
	v.mu.RLock()
	last := v.lastRefresh
	v.mu.RUnlock()
	if !last.IsZero() && now.Sub(last) < v.unknownCooldown {
		return
	}

	v.refreshMu.Lock()
	if ch := v.refreshCh; ch != nil {
		v.refreshMu.Unlock()
		<-ch
		return
	}
	ch := make(chan struct{})
	v.refreshCh = ch
	v.refreshMu.Unlock()

	defer func() {
		v.refreshMu.Lock()
		close(ch)
		v.refreshCh = nil
		v.refreshMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = v.Refresh(ctx)
}

// Verify 使用当前系统时间执行 0 RTT 本地验签。
func (v *OfflineVerifier) Verify(token, rawHost, wantScope string) VerifyResult {
	return v.VerifyAt(v.nowFn().UTC(), token, rawHost, wantScope)
}

// VerifyAt 使用指定时间执行本地验签（便于确定性单元测试）。
func (v *OfflineVerifier) VerifyAt(now time.Time, token, rawHost, wantScope string) VerifyResult {
	nowUnix := now.UTC().Unix()
	host, err := NormalizeHost(rawHost)
	if err != nil {
		return VerifyResult{Valid: false, Code: CodeInvalidHost, ServerTime: nowUnix}
	}
	if wantScope != "" && !ValidScope(wantScope) {
		return VerifyResult{Valid: false, Code: CodeInvalidScope, Host: host, ServerTime: nowUnix}
	}

	// 检查有效令牌内存缓存
	ck := token + "\x00" + host + "\x00" + wantScope
	v.validCacheMu.Lock()
	if cached, ok := v.validCache[ck]; ok {
		if nowUnix >= cached.ExpiresAt {
			delete(v.validCache, ck)
			v.validCacheMu.Unlock()
		} else if nowUnix >= cached.IssuedAt-ClockSkewSec {
			v.validCacheMu.Unlock()
			v.mu.RLock()
			revoked := v.revoked[cached.Kid]
			_, exists := v.keys[cached.Kid]
			v.mu.RUnlock()
			if !revoked && exists {
				cached.ServerTime = nowUnix
				cached.TTLSeconds = cached.ExpiresAt - nowUnix
				return cached
			}
		} else {
			v.validCacheMu.Unlock()
		}
	} else {
		v.validCacheMu.Unlock()
	}

	hdr, cl, signingInput, sig, ok := parseCompactJWT(token)
	if !ok || hdr.Alg != AlgEdDSA || hdr.Kid == "" {
		return VerifyResult{Valid: false, Code: CodeInvalidToken, Host: host, ServerTime: nowUnix}
	}

	v.mu.RLock()
	revoked := v.revoked[hdr.Kid]
	pub, found := v.keys[hdr.Kid]
	v.mu.RUnlock()

	if revoked {
		return VerifyResult{Valid: false, Code: CodeRevoked, Host: host, ServerTime: nowUnix}
	}
	if !found {
		v.refreshIfCooledDown()
		v.mu.RLock()
		revoked = v.revoked[hdr.Kid]
		pub, found = v.keys[hdr.Kid]
		v.mu.RUnlock()
		if revoked {
			return VerifyResult{Valid: false, Code: CodeRevoked, Host: host, ServerTime: nowUnix}
		}
		if !found {
			return VerifyResult{Valid: false, Code: CodeInvalidToken, Host: host, ServerTime: nowUnix}
		}
	}

	if cl.Iss != Issuer || !ValidScope(cl.Scp) || cl.Iat <= 0 || cl.Exp <= cl.Iat {
		return VerifyResult{Valid: false, Code: CodeInvalidToken, Host: host, ServerTime: nowUnix}
	}
	if nowUnix < cl.Iat-ClockSkewSec {
		return VerifyResult{Valid: false, Code: CodeInvalidToken, Host: host, ServerTime: nowUnix}
	}
	if nowUnix >= cl.Exp {
		return VerifyResult{Valid: false, Code: CodeExpired, Host: host, ServerTime: nowUnix}
	}
	if cl.Aud != host {
		return VerifyResult{Valid: false, Code: CodeHostMismatch, Host: host, ServerTime: nowUnix}
	}
	if wantScope != "" && cl.Scp != wantScope {
		return VerifyResult{Valid: false, Code: CodeScopeMismatch, Host: host, ServerTime: nowUnix}
	}
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return VerifyResult{Valid: false, Code: CodeInvalidToken, Host: host, ServerTime: nowUnix}
	}

	res := VerifyResult{
		Valid:      true,
		Code:       CodeOK,
		Issuer:     Issuer,
		Host:       host,
		Scope:      cl.Scp,
		Kid:        hdr.Kid,
		IssuedAt:   cl.Iat,
		ExpiresAt:  cl.Exp,
		TTLSeconds: cl.Exp - nowUnix,
		ServerTime: nowUnix,
	}

	v.validCacheMu.Lock()
	if len(v.validCache) >= 4096 {
		clear(v.validCache)
	}
	v.validCache[ck] = res
	v.validCacheMu.Unlock()
	return res
}
