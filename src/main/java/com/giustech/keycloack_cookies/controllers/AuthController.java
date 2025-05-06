package com.giustech.keycloack_cookies.controllers;

import com.giustech.keycloack_cookies.dto.LoginDTO;
import com.giustech.keycloack_cookies.service.KeycloakService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    private final KeycloakService keycloakService;

    @PostMapping("/login")
    public void login(@RequestBody LoginDTO loginDTO, HttpServletResponse httpServletResponse) {
        keycloakService.login(loginDTO.username(), loginDTO.password(), httpServletResponse);
    }
}
