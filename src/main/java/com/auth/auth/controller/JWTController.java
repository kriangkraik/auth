package com.auth.auth.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.auth.dto.TokenRequest;
import com.auth.auth.entities.Authentication;

import com.auth.auth.services.JwtService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class JWTController {

    private final JwtService jwt;

    @PostMapping("/getToken")
    public ResponseEntity<Map<String, String>> getToken(@RequestBody @Valid Authentication authentication) {
        String token = jwt.generateToken(authentication);
        Map<String, String> response = new HashMap<>();
        response.put("access_token", token);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/validateToken")
    public ResponseEntity<String> loginToken(@RequestBody TokenRequest req) {
        if (jwt.isTokenValid(req.getAccessToken())) {
            return ResponseEntity.ok("Pass");
        }
        return ResponseEntity.status(401).body("Not Pass");
    }
}
