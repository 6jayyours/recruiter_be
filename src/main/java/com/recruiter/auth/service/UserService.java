package com.recruiter.auth.service;


import com.recruiter.auth.model.User;
import com.recruiter.auth.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository repository;

    public UserService(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByUsername(username).orElseThrow(()-> new UsernameNotFoundException("User not found"));
    }


    public String findRoleByUsername(String username) {
        User user = repository.findByUsername(username).orElse(null);
        return user != null ? user.getRole() : null;
    }

    public Integer findIdByUsername(String username) {
        User user = repository.findByUsername(username).orElse(null);
        return user != null ? user.getId() : null;
    }
}
