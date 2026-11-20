// Spring Boot / Servlet Filter 接入示例（复制进你的 Spring Boot 工程即可使用）
package examples;

import pub.wav.crawlerverify.OfflineVerifier;
import pub.wav.crawlerverify.VerifyResult;

public final class SpringBootFilterExample {
    // 建议注册为全局单例 Bean，在应用退出时调用 offlineVerifier.close()
    private final OfflineVerifier offlineVerifier = OfflineVerifier.builder().build();

    public boolean isVerifiedWavPubRssRequest(String tokenHeader, String requestHost) {
        if (tokenHeader == null || tokenHeader.isEmpty()) {
            return false;
        }
        VerifyResult res = offlineVerifier.verify(tokenHeader, requestHost, "rss");
        return res.isValid();
    }
}
