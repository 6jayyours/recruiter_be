package com.recruiter.auth.controller;


import com.recruiter.auth.model.AuthenticationRequest;
import com.recruiter.auth.model.AuthenticationResponse;
import com.recruiter.auth.model.RegisterRequest;
import com.recruiter.auth.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = ("*"))
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService service) {
        this.authenticationService = service;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authenticationService.register(request));
    }


    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        System.out.println("username" +request.getUsername());
        System.out.println("password" +request.getPassword());
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOtp(@RequestBody Map<String, String> requestBody) {
        String email = requestBody.get("email");
        String otp = requestBody.get("otp");

        System.out.println("email: " + email);
        System.out.println("otp: " + otp);

        boolean verified = authenticationService.verifyOTP(email, otp);

        if (verified) {
            return ResponseEntity.ok("OTP verified successfully.");
        } else {
            return ResponseEntity.badRequest().body("Invalid OTP.");
        }
    }

}
