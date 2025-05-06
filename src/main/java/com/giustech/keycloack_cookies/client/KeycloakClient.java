package com.giustech.keycloack_cookies.client;

import com.giustech.keycloack_cookies.config.FeignFormConfig;
import com.giustech.keycloack_cookies.dto.TokenIntrospectionResponse;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
        name = "keycloakClient",
        url  = "${keycloak.server-url}",
        configuration = FeignFormConfig.class
)
public interface KeycloakClient {

    /* ---------- refresh token ---------- */
    @PostMapping(
            value    = "/realms/{realm}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    AccessTokenResponse refreshToken(
            @PathVariable("realm") String realm,
            @RequestBody MultiValueMap<String, String> form
    );

    /* ---------- introspection ---------- */
    @PostMapping(
            value    = "/realms/{realm}/protocol/openid-connect/token/introspect",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    TokenIntrospectionResponse introspectToken(
            @PathVariable("realm") String realm,
            @RequestBody          MultiValueMap<String, String> form
    );
}