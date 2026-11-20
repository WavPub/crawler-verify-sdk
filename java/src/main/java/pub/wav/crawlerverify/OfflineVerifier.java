package pub.wav.crawlerverify;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 0 RTT 本地 Ed25519 JWKS 离线验签器（JDK 17+ 原生 JCA）。
 */
public final class OfflineVerifier implements Closeable {
    public static final String HEADER_TOKEN = HostNormalizer.HEADER_TOKEN;
    public static final String HEADER_TRACE_ID = HostNormalizer.HEADER_TRACE_ID;
    public static final String DEFAULT_JWKS_URL = "https://wav.pub/.well-known/wavpub-crawler-jwks.json";

    // RFC 8410 Ed25519 SubjectPublicKeyInfo DER 固定 12 字节前缀
    private static final byte[] ED25519_X509_PREFIX = new byte[] {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String jwksUrl;
    private final Duration unknownKidCooldown;
    private final HttpClient httpClient;
    private final ScheduledExecutorService scheduler;
    private final Object refreshLock = new Object();

    private volatile KeySnapshot snapshot = new KeySnapshot(Map.of(), Set.of(), "", 0L);
    private final ConcurrentHashMap<String, VerifyResult> validCache = new ConcurrentHashMap<>();

    private record KeySnapshot(Map<String, PublicKey> keys, Set<String> revoked, String etag, long lastRefreshMs) {}

    public static final class Builder {
        private String jwksUrl = DEFAULT_JWKS_URL;
        private Duration pollInterval = Duration.ofMinutes(5);
        private Duration unknownKidCooldown = Duration.ofSeconds(60);
        private Duration timeout = Duration.ofSeconds(3);
        private boolean startBackground = true;
        private String initialJwksJson = null;

        public Builder jwksUrl(String url) { this.jwksUrl = url; return this; }
        public Builder pollInterval(Duration d) { this.pollInterval = d; return this; }
        public Builder unknownKidCooldown(Duration d) { this.unknownKidCooldown = d; return this; }
        public Builder timeout(Duration d) { this.timeout = d; return this; }
        public Builder startBackground(boolean enable) { this.startBackground = enable; return this; }
        public Builder initialJwksJson(String json) { this.initialJwksJson = json; return this; }

        public OfflineVerifier build() {
            return new OfflineVerifier(this);
        }
    }

    public static Builder builder() { return new Builder(); }

    public static OfflineVerifier fromJwksJson(String jwksJson) {
        return builder().jwksUrl("").startBackground(false).initialJwksJson(jwksJson).build();
    }

    private OfflineVerifier(Builder b) {
        this.jwksUrl = b.jwksUrl == null ? "" : b.jwksUrl;
        this.unknownKidCooldown = b.unknownKidCooldown;
        this.httpClient = HttpClient.newBuilder().connectTimeout(b.timeout).build();

        if (b.initialJwksJson != null) {
            try {
                loadJwks(b.initialJwksJson, "");
            } catch (Exception e) {
                throw new IllegalArgumentException("invalid initial JWKS JSON", e);
            }
        } else if (!this.jwksUrl.isEmpty()) {
            try {
                refresh();
            } catch (Exception ignored) {
                // 启动容错，后台定时刷新自动恢复
            }
        }

        if (b.startBackground && !this.jwksUrl.isEmpty()) {
            long secs = Math.max(10L, b.pollInterval.toSeconds());
            this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "wavpub-jwks-poller");
                t.setDaemon(true);
                return t;
            });
            this.scheduler.scheduleAtFixedRate(() -> {
                try {
                    refresh();
                } catch (Exception ignored) {}
            }, secs, secs, TimeUnit.SECONDS);
        } else {
            this.scheduler = null;
        }
    }

    @Override
    public void close() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    public void loadJwks(String rawJson, String etag) throws Exception {
        JsonNode doc = MAPPER.readTree(rawJson);
        Set<String> revoked = new HashSet<>();
        JsonNode revArr = doc.path("revoked_kids");
        if (revArr.isArray()) {
            for (JsonNode n : revArr) {
                String k = n.asText("");
                if (!k.isEmpty()) revoked.add(k);
            }
        }
        Map<String, PublicKey> keys = new HashMap<>();
        JsonNode keysArr = doc.path("keys");
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        if (keysArr.isArray()) {
            for (JsonNode item : keysArr) {
                if (!"OKP".equals(item.path("kty").asText()) || !"Ed25519".equals(item.path("crv").asText())) {
                    continue;
                }
                String kid = item.path("kid").asText("");
                if (kid.isEmpty() || revoked.contains(kid)) continue;
                byte[] rawPub = Base64.getUrlDecoder().decode(item.path("x").asText(""));
                if (rawPub.length != 32) continue;
                byte[] der = new byte[ED25519_X509_PREFIX.length + 32];
                System.arraycopy(ED25519_X509_PREFIX, 0, der, 0, ED25519_X509_PREFIX.length);
                System.arraycopy(rawPub, 0, der, ED25519_X509_PREFIX.length, 32);
                keys.put(kid, kf.generatePublic(new X509EncodedKeySpec(der)));
            }
        }
        this.snapshot = new KeySnapshot(
                Collections.unmodifiableMap(keys),
                Collections.unmodifiableSet(revoked),
                etag == null ? "" : etag,
                System.currentTimeMillis());
        this.validCache.clear();
    }

    public void refresh() throws IOException, InterruptedException {
        if (jwksUrl.isEmpty()) return;
        KeySnapshot cur = this.snapshot;
        HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(jwksUrl))
                .GET()
                .timeout(Duration.ofSeconds(3));
        if (!cur.etag().isEmpty()) {
            rb.header("If-None-Match", cur.etag());
        }
        HttpResponse<String> resp = httpClient.send(rb.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (resp.statusCode() == 304) {
            this.snapshot = new KeySnapshot(cur.keys(), cur.revoked(), cur.etag(), System.currentTimeMillis());
            return;
        }
        if (resp.statusCode() != 200) {
            throw new IOException("JWKS HTTP " + resp.statusCode());
        }
        String newEtag = resp.headers().firstValue("ETag").orElse(cur.etag());
        try {
            loadJwks(resp.body(), newEtag);
        } catch (Exception e) {
            throw new IOException("parse JWKS failed", e);
        }
    }

    private void refreshIfCooledDown() {
        if (jwksUrl.isEmpty()) return;
        long nowMs = System.currentTimeMillis();
        if (nowMs - snapshot.lastRefreshMs() < unknownKidCooldown.toMillis()) {
            return;
        }
        synchronized (refreshLock) {
            nowMs = System.currentTimeMillis();
            if (nowMs - snapshot.lastRefreshMs() < unknownKidCooldown.toMillis()) {
                return;
            }
            try {
                refresh();
            } catch (Exception ignored) {
                KeySnapshot cur = this.snapshot;
                this.snapshot = new KeySnapshot(cur.keys(), cur.revoked(), cur.etag(), System.currentTimeMillis());
            }
        }
    }

    public VerifyResult verify(String token, String host, String scope) {
        return verifyAt(Instant.now().getEpochSecond(), token, host, scope);
    }

    public VerifyResult verifyAt(long nowUnix, String token, String rawHost, String wantScope) {
        String host = HostNormalizer.normalize(rawHost);
        if (host == null) {
            return VerifyResult.reject("invalid_host", "", nowUnix, false);
        }
        String scope = wantScope == null ? "" : wantScope;
        if (!scope.isEmpty() && !HostNormalizer.validScope(scope)) {
            return VerifyResult.reject("invalid_scope", host, nowUnix, false);
        }

        KeySnapshot snap = this.snapshot;
        String ck = token + "\0" + host + "\0" + scope;
        VerifyResult cached = validCache.get(ck);
        if (cached != null) {
            if (nowUnix >= cached.getExpiresAt()
                    || snap.revoked().contains(cached.getKid())
                    || !snap.keys().containsKey(cached.getKid())) {
                validCache.remove(ck);
            } else if (nowUnix >= cached.getIssuedAt() - HostNormalizer.CLOCK_SKEW_SEC) {
                return new VerifyResult(
                        true, "ok", cached.getIssuer(), cached.getHost(), cached.getScope(), cached.getKid(),
                        cached.getIssuedAt(), cached.getExpiresAt(),
                        Math.max(0, cached.getExpiresAt() - nowUnix), nowUnix, false);
            }
        }

        if (!HostNormalizer.looksLikeJwt(token)) {
            return VerifyResult.reject("invalid_token", host, nowUnix, false);
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return VerifyResult.reject("invalid_token", host, nowUnix, false);
        }

        JsonNode hdr;
        JsonNode cl;
        byte[] sig;
        try {
            hdr = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[0]));
            cl = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[1]));
            sig = Base64.getUrlDecoder().decode(parts[2]);
        } catch (Exception e) {
            return VerifyResult.reject("invalid_token", host, nowUnix, false);
        }
        if (sig.length != 64 || !HostNormalizer.ALG_EDDSA.equals(hdr.path("alg").asText())) {
            return VerifyResult.reject("invalid_token", host, nowUnix, false);
        }
        String kid = hdr.path("kid").asText("");
        if (kid.isEmpty()) {
            return VerifyResult.reject("invalid_token", host, nowUnix, false);
        }

        if (snap.revoked().contains(kid)) {
            return VerifyResult.reject("revoked", host, nowUnix, false);
        }
        PublicKey pub = snap.keys().get(kid);
        if (pub == null) {
            refreshIfCooledDown();
            snap = this.snapshot;
            if (snap.revoked().contains(kid)) {
                return VerifyResult.reject("revoked", host, nowUnix, false);
            }
            pub = snap.keys().get(kid);
            if (pub == null) {
                return VerifyResult.reject("invalid_token", host, nowUnix, false);
            }
        }

        String iss = cl.path("iss").asText("");
        String scp = cl.path("scp").asText("");
        String aud = cl.path("aud").asText("");
        long iat = cl.path("iat").asLong(0);
        long exp = cl.path("exp").asLong(0);
        if (!HostNormalizer.ISSUER.equals(iss) || !HostNormalizer.validScope(scp) || iat <= 0 || exp <= iat) {
            return VerifyResult.reject("invalid_token", host, nowUnix, false);
        }
        if (nowUnix < iat - HostNormalizer.CLOCK_SKEW_SEC) {
            return VerifyResult.reject("invalid_token", host, nowUnix, false);
        }
        if (nowUnix >= exp) {
            return VerifyResult.reject("expired", host, nowUnix, false);
        }
        if (!host.equals(aud)) {
            return VerifyResult.reject("host_mismatch", host, nowUnix, false);
        }
        if (!scope.isEmpty() && !scope.equals(scp)) {
            return VerifyResult.reject("scope_mismatch", host, nowUnix, false);
        }

        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(pub);
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(sig)) {
                return VerifyResult.reject("invalid_token", host, nowUnix, false);
            }
        } catch (Exception e) {
            return VerifyResult.reject("invalid_token", host, nowUnix, false);
        }

        VerifyResult okRes = new VerifyResult(
                true, "ok", HostNormalizer.ISSUER, host, scp, kid,
                iat, exp, Math.max(0, exp - nowUnix), nowUnix, false);
        if (validCache.size() >= 4096) {
            validCache.clear();
        }
        validCache.put(ck, okRes);
        return okRes;
    }
}
