package com.giustech.keycloack_cookies.filter;

import com.giustech.keycloack_cookies.service.KeycloakService;
import com.giustech.keycloack_cookies.util.TokenUtils;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.RefreshToken;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class CookieFilter implements Filter {
    private static final String COOKIE_ACCESS_TOKEN_NAME = "giustech-cookie-at";
    private static final String COOKIE_REFRESH_TOKEN_NAME = "giustech-cookie-rt";
    private static final String BEARER_PREFIX = "Bearer ";
    private final KeycloakService keycloakService;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String path = httpRequest.getRequestURI();

        if (isPublicPath(path)) {
            chain.doFilter(request, response);
            return;
        }

        String accessToken = getAccessTokenFromCookie(httpRequest);
        String refreshToken = getRefreshTokenFromCookie(httpRequest);
        String tokenToUse = accessToken;

        if (accessToken != null && !isAccessTokenExpired(accessToken)) {
            log.info("access token is valid");
            if (!keycloakService.verifyIfTokenIsValid(accessToken)) {
                log.info("access token is invalid");
                clearAuthCookies(httpResponse);
                log.debug("invalid access token");
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid access token");
                return;
            }
        } else if (accessToken == null || isAccessTokenExpired(accessToken)) {
            if (refreshToken != null && !isRefreshTokenExpired(refreshToken)) {
                try {
                    log.info("refreshing token");
                    AccessTokenResponse tokenResponse = keycloakService.refreshToken(refreshToken);
                    if (tokenResponse != null) {
                        updateTokenCookies(httpResponse, tokenResponse);
                        tokenToUse = tokenResponse.getToken();
                    }
                } catch (Exception e) {
                    log.error("something went wrong: {}", e.getMessage());
                    clearAuthCookies(httpResponse);
                    httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "some error occurred");
                    return;
                }
            } else {
                log.debug("No hay refresh token válido. Sesión expirada");
                clearAuthCookies(httpResponse);
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session expired");
                return;
            }
        }

        if (tokenToUse == null) {
            clearAuthCookies(httpResponse);
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session expired");
            return;
        }

        ModifiedRequest modifiedRequest = new ModifiedRequest(httpRequest, tokenToUse);
        chain.doFilter(modifiedRequest, response);
    }

    private boolean isRefreshTokenExpired(String token) {
        try {
            RefreshToken rt = TokenUtils.parseToRefreshTokenObject(token);
            long exp = rt.getExp();
            long now = System.currentTimeMillis() / 1000;
            return exp < now;
        } catch (Exception e) {
            log.error("Something went wrong : {}", e.getMessage());
            return true;
        }
    }

    private void updateTokenCookies(HttpServletResponse response, AccessTokenResponse tokenResponse) {
        Cookie access = new Cookie(COOKIE_ACCESS_TOKEN_NAME, tokenResponse.getToken());
        access.setPath("/");
        access.setHttpOnly(true);
        access.setSecure(false);
        access.setMaxAge((int) tokenResponse.getExpiresIn());
        response.addCookie(access);

        Cookie refresh = new Cookie(COOKIE_REFRESH_TOKEN_NAME, tokenResponse.getRefreshToken());
        refresh.setPath("/");
        refresh.setHttpOnly(true);
        refresh.setSecure(false);
        refresh.setMaxAge((int) tokenResponse.getRefreshExpiresIn());
        response.addCookie(refresh);

        log.debug("Token cookies updated");
    }
    private void clearAuthCookies(HttpServletResponse response) {
        Cookie access = new Cookie(COOKIE_ACCESS_TOKEN_NAME, "");
        access.setPath("/");
        access.setHttpOnly(true);
        access.setMaxAge(0);
        response.addCookie(access);

        Cookie refresh = new Cookie(COOKIE_REFRESH_TOKEN_NAME, "");
        refresh.setPath("/");
        refresh.setHttpOnly(true);
        refresh.setMaxAge(0);
        response.addCookie(refresh);

        log.debug("Auth cookies cleared");
    }

    private boolean isPublicPath(String path) {
        return pathMatcher.match("/api/auth/login", path);
    }

    private String getAccessTokenFromCookie(HttpServletRequest req) {
        return getCookieValue(req, COOKIE_ACCESS_TOKEN_NAME).orElse(null);
    }

    private String getRefreshTokenFromCookie(HttpServletRequest req) {
        return getCookieValue(req, COOKIE_REFRESH_TOKEN_NAME).orElse(null);
    }

    private boolean isAccessTokenExpired(String token) {
        try {
            AccessToken at = TokenUtils.parseToAccessTokenObject(token);
            long exp = at.getExp();
            long now = System.currentTimeMillis() / 1000;
            return exp - 160 < now;
        } catch (Exception e) {
            log.error("Something went wrong: {}", e.getMessage());
            return true;
        }
    }

    private Optional<String> getCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if (name.equals(c.getName())) {
                    return Optional.ofNullable(c.getValue());
                }
            }
        }
        return Optional.empty();
    }

    private static class ModifiedRequest extends HttpServletRequestWrapper {
        private final String token;

        ModifiedRequest(HttpServletRequest req, String token) {
            super(req);
            this.token = token;
        }

        @Override
        public String getHeader(String name) {
            if ("Authorization".equalsIgnoreCase(name)) {
                return BEARER_PREFIX + token;
            }
            return super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if ("Authorization".equalsIgnoreCase(name)) {
                return Collections.enumeration(Collections.singletonList(BEARER_PREFIX + token));
            }
            return super.getHeaders(name);
        }
    }
}
