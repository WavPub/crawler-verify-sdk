package pub.wav.crawlerverify;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 在线调用 GET /api/request-verify 的核验器（内置正负缓存、单 IP 失败熔断、500ms 超时 Fail-Normal）。
 */
public final class OnlineVerifier {
    public static final String DEFAULT_VERIFY_URL = "https://wav.pub/api/request-verify";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String verifyUrl;
    private final Duration timeout;
    private final HttpClient httpClient;
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, IpFailState> ipFails = new ConcurrentHashMap<>();

    private record CacheEntry(VerifyResult result, long expiresAtMs) {}

    private static final class IpFailState {
        int count;
        long windowEndMs;
        long blockedEndMs;
    }

    public static final class Builder {
        private String verifyUrl = DEFAULT_VERIFY_URL;
        private Duration timeout = Duration.ofMillis(500);

        public Builder verifyUrl(String url) { this.verifyUrl = url; return this; }
        public Builder timeout(Duration d) { this.timeout = d; return this; }
        public OnlineVerifier build() { return new OnlineVerifier(this); }
    }

    public static Builder builder() { return new Builder(); }

    private OnlineVerifier(Builder b) {
        this.verifyUrl = b.verifyUrl;
        this.timeout = b.timeout;
        this.httpClient = HttpClient.newBuilder().connectTimeout(b.timeout).build();
    }

    public VerifyResult verify(String token, String rawHost, String wantScope, String clientIp) {
        long nowMs = System.currentTimeMillis();
        long nowUnix = Instant.ofEpochMilli(nowMs).getEpochSecond();

        String host = HostNormalizer.normalize(rawHost);
        if (host == null) {
            return VerifyResult.reject("invalid_host", "", nowUnix, false);
        }
        String scope = wantScope == null ? "" : wantScope;
        if (!scope.isEmpty() && !HostNormalizer.validScope(scope)) {
            return VerifyResult.reject("invalid_scope", host, nowUnix, false);
        }
        if (!HostNormalizer.looksLikeJwt(token)) {
            recordIpFail(clientIp, nowMs);
            return VerifyResult.reject("invalid_token", host, nowUnix, false);
        }
        if (isIpBlocked(clientIp, nowMs)) {
            return VerifyResult.reject("ip_circuit_open", host, nowUnix, false);
        }

        String ck = cacheKey(token, host, scope);
        CacheEntry cached = cache.get(ck);
        if (cached != null) {
            if (nowMs < cached.expiresAtMs()) {
                return cached.result();
            }
            cache.remove(ck);
        }

        String sep = verifyUrl.contains("?") ? "&" : "?";
        StringBuilder sb = new StringBuilder(verifyUrl)
                .append(sep).append("token=").append(URLEncoder.encode(token, StandardCharsets.UTF_8))
                .append("&host=").append(URLEncoder.encode(host, StandardCharsets.UTF_8));
        if (!scope.isEmpty()) {
            sb.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
        }

        HttpRequest req = HttpRequest.newBuilder(URI.create(sb.toString()))
                .GET()
                .timeout(timeout)
                .build();
        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return VerifyResult.reject("service_unavailable", host, nowUnix, true);
        }

        JsonNode data = null;
        try {
            data = MAPPER.readTree(resp.body());
        } catch (Exception ignored) {}

        String respHost = data != null && !data.path("host").asText("").isEmpty() ? data.path("host").asText() : host;
        if (resp.statusCode() == 200 && data != null && data.path("valid").asBoolean(false) && host.equals(respHost)) {
            long ttl = data.path("ttl_seconds").asLong(0);
            VerifyResult ok = new VerifyResult(
                    true,
                    data.path("code").asText("ok"),
                    data.path("issuer").asText(HostNormalizer.ISSUER),
                    respHost,
                    data.path("scope").asText(""),
                    data.path("kid").asText(""),
                    data.path("issued_at").asLong(0),
                    data.path("expires_at").asLong(0),
                    ttl,
                    data.path("server_time").asLong(nowUnix),
                    false);
            long cacheSec = Math.min(Math.max(0, ttl - 5), 300);
            if (cacheSec > 0) {
                putCache(ck, ok, nowMs + cacheSec * 1000L);
            }
            return ok;
        }
        if (resp.statusCode() == 400 || resp.statusCode() == 403) {
            String code = data != null ? data.path("code").asText("invalid_token") : "invalid_token";
            VerifyResult bad = VerifyResult.reject(code, respHost, nowUnix, false);
            putCache(ck, bad, nowMs + 60_000L);
            recordIpFail(clientIp, nowMs);
            return bad;
        }
        String code = resp.statusCode() == 429 ? "rate_limited" : "service_unavailable";
        return VerifyResult.reject(code, respHost, nowUnix, true);
    }

    private void putCache(String ck, VerifyResult res, long expMs) {
        if (cache.size() >= 8192) {
            cache.clear();
        }
        cache.put(ck, new CacheEntry(res, expMs));
    }

    private static String cacheKey(String token, String host, String scope) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest((token + "\0" + host + "\0" + scope).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(dig, 0, 16);
        } catch (Exception e) {
            return token + "|" + host + "|" + scope;
        }
    }

    private boolean isIpBlocked(String ip, long nowMs) {
        if (ip == null || ip.isEmpty()) return false;
        IpFailState st = ipFails.get(ip);
        return st != null && nowMs < st.blockedEndMs;
    }

    private void recordIpFail(String ip, long nowMs) {
        if (ip == null || ip.isEmpty()) return;
        if (ipFails.size() >= 8192) ipFails.clear();
        ipFails.compute(ip, (k, st) -> {
            if (st == null || nowMs > st.windowEndMs) {
                IpFailState n = new IpFailState();
                n.count = 1;
                n.windowEndMs = nowMs + 60_000L;
                return n;
            }
            st.count++;
            if (st.count >= 3) {
                st.blockedEndMs = nowMs + 600_000L;
            }
            return st;
        });
    }
}
