package cncs.academy.ess.service;

import cncs.academy.ess.model.User;
import cncs.academy.ess.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TodoUserServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void login_shouldReturnValidJWTTokenWhenCredentialsMatch() throws Exception {
        // Arrange (mock do repositório)
        UserRepository repo = Mockito.mock(UserRepository.class);
        TodoUserService service = new TodoUserService(repo);

        String username = "ricardo";
        String password = "123";

        User u = new User(username, password);
        u.setId(7);

        when(repo.findByUsername(username)).thenReturn(u);

        // Act
        String token = service.login(username, password);

        // Assert (1) "Bearer" no início
        assertNotNull(token, "token não deve ser null quando as credenciais batem");
        assertTrue(token.startsWith("Bearer "), "token deve começar por 'Bearer '");

        // extrai só o JWT (a parte após 'Bearer ')
        String jwt = token.substring("Bearer ".length()).trim();

        // Assert (2) o resto é um JWT com a estrutura de claims correta
        assertIsJwt(jwt);

        JsonNode header = jwtHeader(jwt);
        JsonNode payload = jwtPayload(jwt);

        // Header típico JWT
        assertEquals("JWT", header.path("typ").asText(), "header.typ deve ser 'JWT'");
        assertTrue(
                header.hasNonNull("alg"),
                "header.alg deve existir (ex.: HS256, RS256, etc.)"
        );

        // Claims mínimos recomendados (ajusta ao teu requisito)
        assertEquals(username, payload.path("sub").asText(), "payload.sub deve ser o username");
        assertEquals(7, payload.path("uid").asInt(), "payload.uid deve ser o id do utilizador");

        // iat/exp são comuns (se os implementares)
        assertTrue(payload.hasNonNull("iat"), "payload.iat deve existir (issued-at)");
        assertTrue(payload.hasNonNull("exp"), "payload.exp deve existir (expiry)");

        // Verifica que o repositório foi usado como esperado
        verify(repo, times(1)).findByUsername(username);
        verifyNoMoreInteractions(repo);
    }

    // ---------- helpers de validação JWT ----------

    private static void assertIsJwt(String jwt) {
        assertNotNull(jwt);
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length, "JWT deve ter 3 partes (header.payload.signature)");
        assertFalse(parts[0].isBlank(), "header não pode ser vazio");
        assertFalse(parts[1].isBlank(), "payload não pode ser vazio");
        assertFalse(parts[2].isBlank(), "signature não pode ser vazia");
    }

    private static JsonNode jwtHeader(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        return decodeBase64UrlJson(parts[0]);
    }

    private static JsonNode jwtPayload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        return decodeBase64UrlJson(parts[1]);
    }

    private static JsonNode decodeBase64UrlJson(String base64Url) throws Exception {
        byte[] decoded = Base64.getUrlDecoder().decode(base64Url);
        String json = new String(decoded, StandardCharsets.UTF_8);
        return MAPPER.readTree(json);
    }
}
