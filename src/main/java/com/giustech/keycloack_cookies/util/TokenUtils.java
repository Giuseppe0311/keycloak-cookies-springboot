package com.giustech.keycloack_cookies.util;

import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.util.JsonSerialization;

import java.util.Base64;

public class TokenUtils {

    public static AccessToken parseToAccessTokenObject(String token) {
        AccessToken accessToken;
        try {
            accessToken = JsonSerialization.readValue(
                    new String(Base64.getUrlDecoder().decode(token.split("\\.")[1])),
                    AccessToken.class
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse token");
        }
        return accessToken;
    }


    public static RefreshToken parseToRefreshTokenObject(String token) {
        RefreshToken refreshToken;
        try {
            refreshToken = JsonSerialization.readValue(
                    new String(Base64.getUrlDecoder().decode(token.split("\\.")[1])),
                    RefreshToken.class
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse token");
        }
        return refreshToken;
    }
}
