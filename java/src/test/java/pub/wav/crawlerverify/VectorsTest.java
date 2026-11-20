package pub.wav.crawlerverify;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class VectorsTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void sharedVectorsOffline() throws Exception {
        String raw = Files.readString(Path.of("..", "spec", "vectors.json"), StandardCharsets.UTF_8);
        JsonNode root = MAPPER.readTree(raw);
        OfflineVerifier verifier = OfflineVerifier.fromJwksJson(root.get("jwks").toString());

        for (JsonNode tc : root.get("cases")) {
            String name = tc.get("name").asText();
            VerifyResult res = verifier.verifyAt(
                    tc.get("now_unix").asLong(),
                    tc.get("token").asText(),
                    tc.get("host").asText(),
                    tc.get("scope").asText());
            assertEquals(tc.get("want_valid").asBoolean(), res.isValid(), name);
            assertEquals(tc.get("want_code").asText(), res.getCode(), name);
            assertEquals(tc.get("want_host").asText(), res.getHost(), name);
            if (tc.hasNonNull("want_scope") && !tc.get("want_scope").asText().isEmpty()) {
                assertEquals(tc.get("want_scope").asText(), res.getScope(), name);
            }
            if (tc.hasNonNull("want_kid") && !tc.get("want_kid").asText().isEmpty()) {
                assertEquals(tc.get("want_kid").asText(), res.getKid(), name);
            }
        }
    }

    @Test
    void onlineVerifierCacheAndIpCircuitBreaker() throws Exception {
        String raw = Files.readString(Path.of("..", "spec", "vectors.json"), StandardCharsets.UTF_8);
        String validToken = MAPPER.readTree(raw).get("cases").get(0).get("token").asText();

        AtomicInteger calls = new AtomicInteger();
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/api/request-verify", ex -> {
            calls.incrementAndGet();
            String q = ex.getRequestURI().getRawQuery();
            byte[] body;
            int status;
            if (q != null && q.contains("token=" + validToken) && q.contains("host=feed.xyzcdn.net")) {
                status = 200;
                long exp = Instant.now().getEpochSecond() + 300;
                body = ("{\"valid\":true,\"code\":\"ok\",\"host\":\"feed.xyzcdn.net\",\"scope\":\"rss\",\"expires_at\":" + exp + ",\"ttl_seconds\":300}")
                        .getBytes(StandardCharsets.UTF_8);
            } else {
                status = 403;
                body = "{\"valid\":false,\"code\":\"invalid_token\",\"host\":\"feed.xyzcdn.net\"}".getBytes(StandardCharsets.UTF_8);
            }
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(status, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        srv.start();
        try {
            OnlineVerifier ov = OnlineVerifier.builder()
                    .verifyUrl("http://127.0.0.1:" + srv.getAddress().getPort() + "/api/request-verify")
                    .build();
            VerifyResult r1 = ov.verify(validToken, "FEED.XYZCDN.NET", "rss", "1.2.3.4");
            VerifyResult r2 = ov.verify(validToken, "feed.xyzcdn.net", "rss", "1.2.3.4");
            assertTrue(r1.isValid());
            assertTrue(r2.isValid());
            assertEquals(1, calls.get());

            for (int i = 0; i < 3; i++) {
                ov.verify("not.a.jwt", "feed.xyzcdn.net", "rss", "9.9.9.9");
            }
            int before = calls.get();
            VerifyResult blocked = ov.verify(validToken, "feed.xyzcdn.net", "rss", "9.9.9.9");
            assertFalse(blocked.isValid());
            assertEquals("ip_circuit_open", blocked.getCode());
            assertEquals(before, calls.get());
        } finally {
            srv.stop(0);
        }
    }
}
