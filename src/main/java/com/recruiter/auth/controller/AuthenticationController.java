package com.recruiter.auth.controller;


import com.recruiter.auth.model.AuthenticationRequest;
import com.recruiter.auth.model.RegisterRequest;
import com.recruiter.auth.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = ("*"))
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService service) {
        this.authenticationService = service;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestBody RegisterRequest request
    ) {
        String token = authenticationService.register(request);
        return ResponseEntity.ok(token);
    }


    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        String token = authenticationService.authenticate(request);
        return ResponseEntity.ok(token);
    }
}
