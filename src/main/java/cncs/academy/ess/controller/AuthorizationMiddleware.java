package cncs.academy.ess.controller;

import cncs.academy.ess.repository.UserRepository;
import cncs.academy.ess.security.JwtUtil;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.http.HandlerType;
import io.javalin.http.UnauthorizedResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthorizationMiddleware implements Handler {
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationMiddleware.class);
    private final UserRepository userRepository;

    public AuthorizationMiddleware(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void handle(Context ctx) throws Exception {
        // if method is OPTIONS bypass auth middleware
        if (ctx.method() == HandlerType.OPTIONS) {
            // Optionally: validate if it is a legitimate CORS preflight
            return;
        }

        // Allow unauthenticated requests to /user (register) and /login
        if (ctx.path().equals("/user") && ctx.method().name().equals("POST") ||
                ctx.path().equals("/login") && ctx.method().name().equals("POST"))
            return;

        // Check if authorization header exists
        String authorizationHeader = ctx.header("Authorization");
        String path = ctx.path();
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            logger.info("Authorization header is missing or invalid '{}' for path '{}'", authorizationHeader, path);
            throw new UnauthorizedResponse();
        }

        // Extract token from authorization header
        String token = authorizationHeader.substring(7); // Remove "Bearer "

        // Check if token is valid (JWT signature + exp)
        JwtUtil.JwtClaims claims = validateToken(token);
        int userId = claims.valid() ? claims.uid() : -1;
        if (userId == -1) {
            logger.info("Authorization token is invalid {}", token  );
            throw new UnauthorizedResponse();
        }

        // Add user ID to context for use in route handlers
        ctx.attribute("userId", userId);
        ctx.attribute("username", claims.sub());
    }

    /**
     * Validates an HS256 JWT and returns the parsed claims.
     *
     * <p>We keep the repository in the middleware constructor because other versions of the project
     * may still need it, but JWT validation itself does not require a repository lookup.</p>
     */
    private JwtUtil.JwtClaims validateToken(String token) {
        JwtUtil.JwtClaims claims = JwtUtil.validateHs256(JwtUtil.defaultSecret(), token);
        if (!claims.valid()) return claims;

        // Optional safety check: ensure the user still exists.
        // (E.g., token might be valid but user deleted.)
        if (userRepository.findById(claims.uid()) == null) {
            return JwtUtil.JwtClaims.invalid("User not found");
        }
        return claims;
    }
}

