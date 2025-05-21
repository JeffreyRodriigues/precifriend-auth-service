package com.example.precifriend.auth_service.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.precifriend.auth_service.service.AuthService;
import com.example.precifriend.auth_service.service.JwtService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtService jwtService;

    @PostMapping("/register")
    public String register(@RequestBody AuthRequest request) {
        try {
            System.out.println("Recebido: " + request.getUsername());
            authService.register(request.getUsername(), request.getPassword());
            return "Usuário registrado com sucesso!";
        } catch (Exception e) {
            e.printStackTrace();  // imprime erro no console
            return "Erro ao registrar usuário: " + e.getMessage();
        }
    }


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login ou senha inválidos");
        }

        final UserDetails userDetails = authService.loadUserByUsername(request.getUsername());
        String jwt = jwtService.generateToken(userDetails.getUsername());
        return ResponseEntity.ok(jwt);
    }



    public static class AuthRequest {
        private String username;
        private String password;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
}