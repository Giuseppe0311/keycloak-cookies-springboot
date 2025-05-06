package com.giustech.keycloack_cookies.service;

import com.giustech.keycloack_cookies.client.KeycloakClient;
import feign.FeignException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.auth.InvalidCredentialsException;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class KeycloakService {

    @Value("${keycloak.client-id}")
    String clientId;

    @Value("${keycloak.client-secret}")
    String clientSecret;

    @Value("${keycloak.realm}")
    String realm;

    @Value("${keycloak.server-url}")
    String serverUrl;

    @Value("${keycloak.grant-type}")
    String grantType;

    private final KeycloakClient keycloakClient;

    public void login(String username, String password, HttpServletResponse httpServletResponse) {
        try (Keycloak userKeycloak = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .username(username)
                .password(password)
                .grantType(OAuth2Constants.PASSWORD)
                .build()
        ) {
            AccessTokenResponse accessToken = userKeycloak.tokenManager().getAccessToken();

            Cookie cookie_accessToken = new Cookie("giustech-cookie-at", accessToken.getToken());
            cookie_accessToken.setPath("/");
            cookie_accessToken.setHttpOnly(true);
            cookie_accessToken.setMaxAge(3600);
            cookie_accessToken.setSecure(false);
            httpServletResponse.addCookie(cookie_accessToken);

            Cookie cookie_refreshToken = new Cookie("giustech-cookie-rt", accessToken.getRefreshToken());
            cookie_refreshToken.setPath("/");
            cookie_refreshToken.setHttpOnly(true);
            cookie_refreshToken.setMaxAge(3600);
            cookie_refreshToken.setSecure(false);
            httpServletResponse.addCookie(cookie_refreshToken);

        } catch (Exception e) {
            throw new RuntimeException("Error al autenticar el usuario", e);
        }
    }

    public AccessTokenResponse refreshToken(String refreshToken) throws InvalidCredentialsException {

        MultiValueMap<String,String> form = new LinkedMultiValueMap<>();
        form.add("grant_type",    "refresh_token");
        form.add("client_id",     clientId);
        form.add("client_secret", clientSecret);
        form.add("refresh_token", refreshToken);

        try {
            return keycloakClient.refreshToken(realm, form);
        } catch (FeignException e) {
            log.error("Refresh token fallido: {}", e.contentUTF8(), e);
            throw new InvalidCredentialsException("Error refreshing token");
        }
    }

    public boolean verifyIfTokenIsValid(String token) {

        MultiValueMap<String,String> form = new LinkedMultiValueMap<>();
        form.add("client_id",     clientId);
        form.add("client_secret", clientSecret);
        form.add("token",         token);

        try {
            return keycloakClient.introspectToken(realm, form).active();
        } catch (FeignException e) {
            log.error("Something went wrong : {}", e.contentUTF8(), e);
            return false;
        }
    }
}
