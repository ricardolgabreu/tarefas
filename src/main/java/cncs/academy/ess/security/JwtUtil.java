package cncs.academy.ess.security;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minimal JWT (JWS) utility for HS256 tokens.
 *
 * <p>It generates tokens in the format: <code>header.payload.signature</code>, where header and payload
 * are Base64Url-encoded JSON, and signature is HMAC-SHA256 over <code>header.payload</code>.</p>
 *
 * <p>Designed for coursework/demo usage without external JWT libs. In production, prefer a vetted
 * library (e.g. Nimbus JOSE + JWT) and proper key management.</p>
 */
public final class JwtUtil {

    /**
     * Environment variable name used to override the default secret.
     *
     * <p>Example: set JWT_SECRET="a-very-long-random-secret"</p>
     */
    public static final String ENV_JWT_SECRET = "JWT_SECRET";

    /** Default TTL (seconds) for issued tokens. */
    public static final long DEFAULT_TTL_SECONDS = 60L * 60L; // 1 hour

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private JwtUtil() {
    }

    /**
     * Returns the secret used for token signing.
     * <p>If {@link #ENV_JWT_SECRET} is set, uses that; otherwise uses a development fallback.</p>
     */
    public static String defaultSecret() {
        String env = System.getenv(ENV_JWT_SECRET);
        if (env != null && !env.isBlank()) return env;
        // Dev fallback: change in real deployments
        return "dev-secret-change-me-please-at-least-32-chars";
    }

    /** Generate an HS256 JWT with minimal standard claims: sub, uid, iat, exp. */
    public static String generateHs256(String secret, String subject, int userId, long ttlSeconds) {
        try {
            long now = Instant.now().getEpochSecond();
            long exp = now + ttlSeconds;

            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", "HS256");
            header.put("typ", "JWT");

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("sub", subject);
            payload.put("uid", userId);
            payload.put("iat", now);
            payload.put("exp", exp);

            String headerJson = MAPPER.writeValueAsString(header);
            String payloadJson = MAPPER.writeValueAsString(payload);

            String headerB64 = B64URL.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String payloadB64 = B64URL.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

            String signingInput = headerB64 + "." + payloadB64;
            String sigB64 = B64URL.encodeToString(hmacSha256(secret, signingInput));

            return signingInput + "." + sigB64;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JWT", e);
        }
    }

    /**
     * Validate an HS256 JWT: checks format, signature, required claims, and expiration.
     * Returns a {@link JwtClaims} instance describing the result.
     */
    public static JwtClaims validateHs256(String secret, String jwt) {
        try {
            if (jwt == null || jwt.isBlank()) return JwtClaims.invalid("Empty token");

            String[] parts = jwt.split("\\.");
            if (parts.length != 3) return JwtClaims.invalid("Invalid JWT format");

            String signingInput = parts[0] + "." + parts[1];
            byte[] expectedSig = hmacSha256(secret, signingInput);
            byte[] gotSig = B64URL_DEC.decode(parts[2]);

            if (!constantTimeEquals(expectedSig, gotSig)) {
                return JwtClaims.invalid("Invalid signature");
            }

            byte[] payloadBytes = B64URL_DEC.decode(parts[1]);
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = MAPPER.readValue(payloadBytes, Map.class);

            String sub = payload.get("sub") instanceof String s ? s : null;
            Integer uid = payload.get("uid") instanceof Number n ? n.intValue() : null;
            Long exp = payload.get("exp") instanceof Number n ? n.longValue() : null;
            Long iat = payload.get("iat") instanceof Number n ? n.longValue() : null;

            if (sub == null || uid == null || exp == null || iat == null) {
                return JwtClaims.invalid("Missing required claims");
            }

            long now = Instant.now().getEpochSecond();
            if (exp < now) return JwtClaims.invalid("Token expired");

            return JwtClaims.valid(sub, uid, iat, exp);
        } catch (Exception e) {
            return JwtClaims.invalid("Validation error: " + e.getMessage());
        }
    }

    private static byte[] hmacSha256(String secret, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= (a[i] ^ b[i]);
        return r == 0;
    }

    public record JwtClaims(boolean valid, String sub, Integer uid, Long iat, Long exp, String error) {
        public static JwtClaims valid(String sub, int uid, long iat, long exp) {
            return new JwtClaims(true, sub, uid, iat, exp, null);
        }

        public static JwtClaims invalid(String error) {
            return new JwtClaims(false, null, null, null, null, error);
        }
    }
}
