package com.recruiter.auth.service;



import com.recruiter.auth.model.AuthenticationRequest;
import com.recruiter.auth.model.AuthenticationResponse;
import com.recruiter.auth.model.RegisterRequest;
import com.recruiter.auth.model.User;
import com.recruiter.auth.repository.UserRepository;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;



    private JavaMailSender javaMailSender;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(JavaMailSender javaMailSender,UserRepository repository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.javaMailSender = javaMailSender;
        this.userRepository = repository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public AuthenticationResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return new AuthenticationResponse(null,"Username already exists",null);
        }
        String otp = generateOTP();
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEmail(request.getEmail());
        user.setStatus(false);
        user.setOtp(otp);
        user.setRole(request.getRole());
        user = userRepository.save(user);
        sendOTPEmail(user.getEmail(), otp);
//        String jwtToken = jwtService.generateToken( user);
        return new AuthenticationResponse(null,"User registered successfully",null);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );
        } catch (AuthenticationException e) {
            // Authentication failed, return an error response or throw an exception
            return new AuthenticationResponse(null,"Invalid username or password",null);
        }

        User user = userRepository.findByUsername(request.getUsername()).orElseThrow();

        if (!user.isStatus()) {
            // User is blocked or inactive, return an error response or throw an exception
            return new AuthenticationResponse(null,"User is blocked",null);
        }

        String jwtToken = jwtService.generateToken(user);
        return new AuthenticationResponse(jwtToken,"User Registered Successfully",user.getRole());
    }




    public String generateOTP() {
        // Generate a random 6-digit OTP
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            otp.append((int) (Math.random() * 10));
        }
        return otp.toString();
    }

    public void sendOTPEmail(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("marjunramesh@gmail.com"); // Set your email address
        message.setTo(to);
        message.setSubject("OTP Verification");
        message.setText("Your OTP for registration is: " + otp);

        javaMailSender.send(message);
    }

    public boolean verifyOTP(String name, String otp) {
        User user = userRepository.findByEmail(name);

        if (user != null) {
            String storedOtp = user.getOtp();
            if (storedOtp != null && storedOtp.trim().equals(otp.trim())) {
                user.setStatus(true);
                userRepository.save(user);
                return true;
            }
        }
        return false;
    }
}
