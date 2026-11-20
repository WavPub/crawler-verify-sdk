package pub.wav.crawlerverify;

public final class VerifyResult {
    private final boolean valid;
    private final String code;
    private final String issuer;
    private final String host;
    private final String scope;
    private final String kid;
    private final long issuedAt;
    private final long expiresAt;
    private final long ttlSeconds;
    private final long serverTime;
    private final boolean degraded;

    public VerifyResult(
            boolean valid,
            String code,
            String issuer,
            String host,
            String scope,
            String kid,
            long issuedAt,
            long expiresAt,
            long ttlSeconds,
            long serverTime,
            boolean degraded) {
        this.valid = valid;
        this.code = code;
        this.issuer = issuer;
        this.host = host;
        this.scope = scope;
        this.kid = kid;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.ttlSeconds = ttlSeconds;
        this.serverTime = serverTime;
        this.degraded = degraded;
    }

    public static VerifyResult reject(String code, String host, long serverTime, boolean degraded) {
        return new VerifyResult(false, code, "", host == null ? "" : host, "", "", 0, 0, 0, serverTime, degraded);
    }

    public boolean isValid() { return valid; }
    public String getCode() { return code; }
    public String getIssuer() { return issuer; }
    public String getHost() { return host; }
    public String getScope() { return scope; }
    public String getKid() { return kid; }
    public long getIssuedAt() { return issuedAt; }
    public long getExpiresAt() { return expiresAt; }
    public long getTtlSeconds() { return ttlSeconds; }
    public long getServerTime() { return serverTime; }
    public boolean isDegraded() { return degraded; }
}
