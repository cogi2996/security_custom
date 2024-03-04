package com.example.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;
    // thêm field newUser vào phương thức register
//    @PostMapping("/register")
//    public ResponseEntity<AuthenticationResponse> register (@RequestBody RegisterRequest loginRequest) {
//        return ResponseEntity.ok(service.register(loginRequest));
//    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate  (@RequestBody AuthenticationRequest loginRequest) {
        return ResponseEntity.ok(service.authenticate(loginRequest));

    }
}
