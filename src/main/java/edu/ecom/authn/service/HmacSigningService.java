package edu.ecom.authn.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class HmacSigningService {

    private final Mac hmac;

    public HmacSigningService(@Value("${app.secret-key}") String secret) throws Exception {
        this.hmac = Mac.getInstance("HmacSHA256");
        this.hmac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
    }

    public boolean verifySignature(String serviceName, String timestamp, String uri, String httpMethod, String receivedSignature) {
        // 1. Reconstruct the signed message
        String message = generateMessage(serviceName, timestamp, uri, httpMethod);

        // 2. Generate expected signature
        String expectedSignature = calculateSignature(message);

        // 3. Secure comparison (time-constant)
        return MessageDigest.isEqual(
            expectedSignature.getBytes(StandardCharsets.UTF_8),
            receivedSignature.getBytes(StandardCharsets.UTF_8)
        );
    }

    // For signing requests to specific services
    public String generateMessage(String serviceName, String timestamp, String uri, String httpMethod) {
        return String.join("|", serviceName, timestamp, uri, httpMethod);
    }

    public String calculateSignature(String message) {
        try {
            return Hex.encodeHexString(hmac.doFinal(message.getBytes()));
        } catch (Exception e) {
            throw new SecurityException("HMAC calculation failed", e);
        }
    }
}