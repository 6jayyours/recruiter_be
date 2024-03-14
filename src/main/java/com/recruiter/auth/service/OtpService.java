package com.recruiter.auth.service;

import com.recruiter.auth.model.User;
import com.recruiter.auth.repository.UserRepository;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class OtpService {

    private JavaMailSender javaMailSender;

    private UserRepository userRepository;

    public String generateOTP() {
        // Generate a random 6-digit OTP
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < 6; i++) {
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

    public boolean verifyOTP(String email, String otp) {
        User user = userRepository.findByEmail(email);

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
