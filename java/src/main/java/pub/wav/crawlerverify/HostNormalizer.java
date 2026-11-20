package pub.wav.crawlerverify;

import java.net.IDN;
import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class HostNormalizer {
    public static final String HEADER_TOKEN = "X-WavPub-Token";
    public static final String HEADER_TRACE_ID = "X-WavPub-Trace-ID";
    public static final String ISSUER = "wav.pub";
    public static final String ALG_EDDSA = "EdDSA";
    public static final int MAX_TOKEN_LEN = 512;
    public static final long CLOCK_SKEW_SEC = 30;
    public static final Set<String> VALID_SCOPES = Set.of("rss", "cover", "audio");

    private static final Pattern HOST_RE = Pattern.compile("^[a-z0-9._-]+$");
    private static final Pattern JWT_RE = Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{86}$");

    private HostNormalizer() {}

    public static boolean validScope(String scope) {
        return scope != null && VALID_SCOPES.contains(scope);
    }

    public static boolean looksLikeJwt(String token) {
        return token != null && token.length() <= MAX_TOKEN_LEN && JWT_RE.matcher(token).matches();
    }

    public static String normalize(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty() || s.length() > 255) return null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c <= 0x20 || c == 0x7f) return null;
        }

        String host = s;
        if (s.contains("://")) {
            try {
                URI uri = URI.create(s);
                if (uri.getHost() == null || uri.getHost().isEmpty()) return null;
                host = uri.getHost();
            } catch (IllegalArgumentException e) {
                return null;
            }
        } else {
            if (s.indexOf('/') >= 0 || s.indexOf('?') >= 0 || s.indexOf('#') >= 0
                    || s.indexOf('\\') >= 0 || s.indexOf('@') >= 0) {
                return null;
            }
            if (s.startsWith("[")) {
                int end = s.indexOf(']');
                if (end <= 1) return null;
                host = s.substring(1, end);
            } else {
                int firstColon = s.indexOf(':');
                if (firstColon >= 0) {
                    if (s.indexOf(':', firstColon + 1) >= 0) {
                        // bare IPv6
                        host = s;
                    } else {
                        String port = s.substring(firstColon + 1);
                        if (port.isEmpty() || !port.chars().allMatch(Character::isDigit)) return null;
                        host = s.substring(0, firstColon);
                    }
                }
            }
        }

        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.isEmpty()) return null;

        if (host.contains(":")) {
            return host.toLowerCase(Locale.ROOT);
        }

        String ascii;
        try {
            ascii = IDN.toASCII(host).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (ascii.isEmpty() || ascii.length() > 253 || !HOST_RE.matcher(ascii).matches()) {
            return null;
        }
        return ascii;
    }
}
