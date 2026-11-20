// Package wavpubverify 提供声湃（WavPub）抓取器身份验证的 Go SDK（纯标准库，零第三方依赖）。
//
// 支持两种验证模式：
//   - OfflineVerifier（推荐）：0 RTT 本地 Ed25519 JWKS 离线验签，内置 ETag 异步轮询、
//     未知 kid 60 秒冷却单飞刷新、revoked_kids 自动剔除、alg==EdDSA 强制锁定。
//   - OnlineVerifier：调用 GET https://wav.pub/api/request-verify，内置正则快筛、
//     正负 LRU 缓存、singleflight 合并、单 IP 失败熔断与 500ms 超时 Fail-Normal 降级。
package wavpubverify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
)

const (
	HeaderToken   = "X-WavPub-Token"
	HeaderTraceID = "X-WavPub-Trace-ID"

	DefaultJWKSURL   = "https://wav.pub/.well-known/wavpub-crawler-jwks.json"
	DefaultVerifyURL = "https://wav.pub/api/request-verify"

	Issuer       = "wav.pub"
	AlgEdDSA     = "EdDSA"
	MaxTokenLen  = 512
	ClockSkewSec = 30

	ScopeRSS   = "rss"
	ScopeCover = "cover"
	ScopeAudio = "audio"

	CodeOK                 = "ok"
	CodeInvalidToken       = "invalid_token"
	CodeExpired            = "expired"
	CodeHostMismatch       = "host_mismatch"
	CodeScopeMismatch      = "scope_mismatch"
	CodeRevoked            = "revoked"
	CodeInvalidHost        = "invalid_host"
	CodeInvalidScope       = "invalid_scope"
	CodeRateLimited        = "rate_limited"
	CodeServiceUnavailable = "service_unavailable"
	CodeCircuitOpen        = "ip_circuit_open"
)

var ErrInvalidHost = errors.New("wavpubverify: invalid host")

// VerifyResult 表示一次身份核验的结果。
type VerifyResult struct {
	Valid      bool   `json:"valid"`
	Code       string `json:"code"`
	Issuer     string `json:"issuer,omitempty"`
	Host       string `json:"host,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Kid        string `json:"kid,omitempty"`
	IssuedAt   int64  `json:"issued_at,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
	ServerTime int64  `json:"server_time,omitempty"`
	// Degraded 为 true 表示在线验证超时或遭遇 5xx/429，建议调用方 Fail-Normal 退回常规风控。
	Degraded bool `json:"degraded,omitempty"`
}

// ValidScope 判断 scope 是否属于协议定义的取值。
func ValidScope(s string) bool {
	return s == ScopeRSS || s == ScopeCover || s == ScopeAudio
}

// NormalizeHost 归一化 HTTP Host 或 URL 的主机名（去端口/方括号、去末尾点号、转小写）。
func NormalizeHost(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 255 {
		return "", ErrInvalidHost
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return "", ErrInvalidHost
		}
	}
	host := s
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", ErrInvalidHost
		}
		host = u.Hostname()
	} else {
		if strings.ContainsAny(s, "/?#\\@") {
			return "", ErrInvalidHost
		}
		if strings.HasPrefix(s, "[") {
			if h, _, err := net.SplitHostPort(s); err == nil {
				host = h
			} else if strings.HasSuffix(s, "]") {
				host = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
			} else {
				return "", ErrInvalidHost
			}
		} else if strings.Count(s, ":") == 1 {
			if h, _, err := net.SplitHostPort(s); err == nil {
				host = h
			} else {
				return "", ErrInvalidHost
			}
		}
	}
	host = strings.TrimRight(host, ".")
	if host == "" {
		return "", ErrInvalidHost
	}
	if ip := net.ParseIP(host); ip != nil {
		return strings.ToLower(ip.String()), nil
	}
	host = strings.ToLower(host)
	if len(host) > 253 {
		return "", ErrInvalidHost
	}
	for _, r := range host {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return "", ErrInvalidHost
		}
	}
	return host, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Scp string `json:"scp"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// looksLikeJWT 快速 O(1) 语法预检：拒绝明显非 JWT 的垃圾请求头，避免浪费验签或回调。
func looksLikeJWT(token string) bool {
	if len(token) < 40 || len(token) > MaxTokenLen {
		return false
	}
	d1 := strings.IndexByte(token, '.')
	if d1 <= 0 {
		return false
	}
	rest := token[d1+1:]
	d2 := strings.IndexByte(rest, '.')
	if d2 <= 0 {
		return false
	}
	sigPart := rest[d2+1:]
	if strings.IndexByte(sigPart, '.') >= 0 || len(sigPart) != 86 {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func parseCompactJWT(token string) (jwtHeader, jwtClaims, string, []byte, bool) {
	var zeroH jwtHeader
	var zeroC jwtClaims
	if !looksLikeJWT(token) {
		return zeroH, zeroC, "", nil, false
	}
	d1 := strings.IndexByte(token, '.')
	rest := token[d1+1:]
	d2 := strings.IndexByte(rest, '.')

	sig, err := base64.RawURLEncoding.DecodeString(rest[d2+1:])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return zeroH, zeroC, "", nil, false
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(token[:d1])
	if err != nil {
		return zeroH, zeroC, "", nil, false
	}
	clRaw, err := base64.RawURLEncoding.DecodeString(rest[:d2])
	if err != nil {
		return zeroH, zeroC, "", nil, false
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return zeroH, zeroC, "", nil, false
	}
	var cl jwtClaims
	if err := json.Unmarshal(clRaw, &cl); err != nil {
		return zeroH, zeroC, "", nil, false
	}
	return hdr, cl, token[:d1+1+d2], sig, true
}
