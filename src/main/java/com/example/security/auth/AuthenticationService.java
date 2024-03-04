package com.example.security.auth;

import com.example.security.config.JwtService;
import com.example.security.user.Account;
import com.example.security.user.AccountRepository;
import com.example.security.user.User;
import com.example.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final AccountRepository repository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    public AuthenticationResponse register(RegisterRequest request , User newUser  ) {
        var account = Account.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // bởi vì encrypt nên giờ phải decode
                .role(request.getRole())
                .build();
//        repository.save(account);
        newUser.setAccount(account);
        userRepository.save(newUser);
        var jwtToken = jwtService.generateToken(account);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }
    // phương thức này dược định nghĩa đúng sai bởi authenticationManager.authenticationProvider
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        //
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }
}
