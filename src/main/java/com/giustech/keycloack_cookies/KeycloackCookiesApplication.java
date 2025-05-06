package com.giustech.keycloack_cookies;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class KeycloackCookiesApplication {

	public static void main(String[] args) {
		SpringApplication.run(KeycloackCookiesApplication.class, args);
	}

}
