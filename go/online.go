package wavpubverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// OnlineOption 配置 OnlineVerifier。
type OnlineOption func(*OnlineVerifier)

// WithVerifyURL 自定义在线核验端点（默认 https://wav.pub/api/request-verify）。
func WithVerifyURL(u string) OnlineOption {
	return func(v *OnlineVerifier) {
		if u != "" {
			v.verifyURL = u
		}
	}
}

// WithOnlineTimeout 设置单次在线回调总超时（默认 500ms）。
func WithOnlineTimeout(d time.Duration) OnlineOption {
	return func(v *OnlineVerifier) {
		if d > 0 {
			v.timeout = d
		}
	}
}

// WithOnlineHTTPClient 自定义 HTTP 客户端。
func WithOnlineHTTPClient(c *http.Client) OnlineOption {
	return func(v *OnlineVerifier) {
		if c != nil {
			v.httpClient = c
		}
	}
}

type onlineCacheEntry struct {
	res       VerifyResult
	expiresAt time.Time
}

type ipFailState struct {
	count      int
	windowEnd  time.Time
	blockedEnd time.Time
}

type inFlightCall struct {
	done chan struct{}
	res  VerifyResult
}

// OnlineVerifier 调用 GET /api/request-verify 完成在线验证。
//
// 内置四重生产保护：
//  1. 入口 O(1) JWT 语法快筛（拦垃圾头，0 网络消耗）
//  2. 正向缓存 min(ttl-5s, 300s) + 负向缓存 60s + singleflight 合并
//  3. 单来访 IP 失败熔断（1 分钟内 >=3 次无效令牌即熔断 10 分钟不再回源）
//  4. 500ms 超时与 5xx/429 返回 Degraded=true（Fail-Normal 不阻断业务）
type OnlineVerifier struct {
	verifyURL  string
	timeout    time.Duration
	httpClient *http.Client
	nowFn      func() time.Time

	cacheMu sync.Mutex
	cache   map[string]onlineCacheEntry

	ipMu    sync.Mutex
	ipFails map[string]*ipFailState

	sfMu     sync.Mutex
	inFlight map[string]*inFlightCall
}

// NewOnlineVerifier 创建在线核验器。
func NewOnlineVerifier(opts ...OnlineOption) *OnlineVerifier {
	v := &OnlineVerifier{
		verifyURL:  DefaultVerifyURL,
		timeout:    500 * time.Millisecond,
		httpClient: &http.Client{Timeout: 500 * time.Millisecond},
		nowFn:      time.Now,
		cache:      map[string]onlineCacheEntry{},
		ipFails:    map[string]*ipFailState{},
		inFlight:   map[string]*inFlightCall{},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify 核验令牌。clientIP 可选，传入后自动启用单 IP 失败熔断防反射 DDoS。
func (v *OnlineVerifier) Verify(ctx context.Context, token, rawHost, wantScope, clientIP string) VerifyResult {
	now := v.nowFn().UTC()
	nowUnix := now.Unix()

	host, err := NormalizeHost(rawHost)
	if err != nil {
		return VerifyResult{Valid: false, Code: CodeInvalidHost, ServerTime: nowUnix}
	}
	if wantScope != "" && !ValidScope(wantScope) {
		return VerifyResult{Valid: false, Code: CodeInvalidScope, Host: host, ServerTime: nowUnix}
	}
	if !looksLikeJWT(token) {
		v.recordIPFail(clientIP, now)
		return VerifyResult{Valid: false, Code: CodeInvalidToken, Host: host, ServerTime: nowUnix}
	}
	if v.isIPBlocked(clientIP, now) {
		return VerifyResult{Valid: false, Code: CodeCircuitOpen, Host: host, ServerTime: nowUnix}
	}

	ck := cacheKey(token, host, wantScope)
	if res, ok := v.getCache(ck, now); ok {
		return res
	}

	// singleflight 合并窗口切换瞬间的并发回源
	v.sfMu.Lock()
	if call, ok := v.inFlight[ck]; ok {
		v.sfMu.Unlock()
		select {
		case <-call.done:
			return call.res
		case <-ctx.Done():
			return VerifyResult{Valid: false, Code: CodeServiceUnavailable, Host: host, ServerTime: nowUnix, Degraded: true}
		}
	}
	call := &inFlightCall{done: make(chan struct{})}
	v.inFlight[ck] = call
	v.sfMu.Unlock()

	res := v.fetchOnce(ctx, token, host, wantScope, clientIP)

	v.sfMu.Lock()
	call.res = res
	close(call.done)
	delete(v.inFlight, ck)
	v.sfMu.Unlock()
	return res
}

func (v *OnlineVerifier) fetchOnce(ctx context.Context, token, host, wantScope, clientIP string) VerifyResult {
	now := v.nowFn().UTC()
	nowUnix := now.Unix()

	reqCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	u, err := url.Parse(v.verifyURL)
	if err != nil {
		return VerifyResult{Valid: false, Code: CodeServiceUnavailable, Host: host, ServerTime: nowUnix, Degraded: true}
	}
	q := u.Query()
	q.Set("token", token)
	q.Set("host", host)
	if wantScope != "" {
		q.Set("scope", wantScope)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return VerifyResult{Valid: false, Code: CodeServiceUnavailable, Host: host, ServerTime: nowUnix, Degraded: true}
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return VerifyResult{Valid: false, Code: CodeServiceUnavailable, Host: host, ServerTime: nowUnix, Degraded: true}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	var parsed VerifyResult
	_ = json.Unmarshal(body, &parsed)
	if parsed.Host == "" {
		parsed.Host = host
	}
	if parsed.ServerTime == 0 {
		parsed.ServerTime = nowUnix
	}

	ck := cacheKey(token, host, wantScope)
	switch resp.StatusCode {
	case http.StatusOK:
		if parsed.Valid && parsed.Host == host {
			ttl := time.Duration(parsed.TTLSeconds-5) * time.Second
			if ttl > 300*time.Second {
				ttl = 300 * time.Second
			}
			if ttl > 0 {
				v.putCache(ck, parsed, now.Add(ttl))
			}
			return parsed
		}
		parsed.Valid = false
		if parsed.Code == "" {
			parsed.Code = CodeInvalidToken
		}
		return parsed
	case http.StatusForbidden, http.StatusBadRequest:
		parsed.Valid = false
		if parsed.Code == "" {
			parsed.Code = CodeInvalidToken
		}
		v.putCache(ck, parsed, now.Add(60*time.Second))
		v.recordIPFail(clientIP, now)
		return parsed
	default:
		// 429 / 5xx 全部视作降级，不缓存、不阻断业务
		if parsed.Code == "" {
			if resp.StatusCode == http.StatusTooManyRequests {
				parsed.Code = CodeRateLimited
			} else {
				parsed.Code = CodeServiceUnavailable
			}
		}
		parsed.Valid = false
		parsed.Degraded = true
		return parsed
	}
}

func cacheKey(token, host, scope string) string {
	sum := sha256.Sum256([]byte(token + "\x00" + host + "\x00" + scope))
	return hex.EncodeToString(sum[:16])
}

func (v *OnlineVerifier) getCache(k string, now time.Time) (VerifyResult, bool) {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	ent, ok := v.cache[k]
	if !ok {
		return VerifyResult{}, false
	}
	if !now.Before(ent.expiresAt) {
		delete(v.cache, k)
		return VerifyResult{}, false
	}
	res := ent.res
	res.ServerTime = now.Unix()
	if res.Valid && res.ExpiresAt > 0 {
		res.TTLSeconds = res.ExpiresAt - now.Unix()
		if res.TTLSeconds < 0 {
			res.TTLSeconds = 0
		}
	}
	return res, true
}

func (v *OnlineVerifier) putCache(k string, res VerifyResult, exp time.Time) {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	if len(v.cache) >= 8192 {
		clear(v.cache)
	}
	v.cache[k] = onlineCacheEntry{res: res, expiresAt: exp}
}

func (v *OnlineVerifier) isIPBlocked(ip string, now time.Time) bool {
	if ip == "" {
		return false
	}
	v.ipMu.Lock()
	defer v.ipMu.Unlock()
	st, ok := v.ipFails[ip]
	if !ok {
		return false
	}
	if !st.blockedEnd.IsZero() && now.Before(st.blockedEnd) {
		return true
	}
	return false
}

func (v *OnlineVerifier) recordIPFail(ip string, now time.Time) {
	if ip == "" {
		return
	}
	v.ipMu.Lock()
	defer v.ipMu.Unlock()
	if len(v.ipFails) >= 8192 {
		clear(v.ipFails)
	}
	st, ok := v.ipFails[ip]
	if !ok || now.After(st.windowEnd) {
		v.ipFails[ip] = &ipFailState{count: 1, windowEnd: now.Add(time.Minute)}
		return
	}
	st.count++
	if st.count >= 3 {
		st.blockedEnd = now.Add(10 * time.Minute)
	}
}
