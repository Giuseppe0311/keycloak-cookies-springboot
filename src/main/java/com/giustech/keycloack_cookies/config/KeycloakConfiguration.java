package com.giustech.keycloack_cookies.config;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakConfiguration {
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

    @Bean
    public Keycloak keycloak() {
        return KeycloakBuilder.builder()
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(grantType)
                .realm(realm)
                .serverUrl(serverUrl)
                .build();
    }
}
