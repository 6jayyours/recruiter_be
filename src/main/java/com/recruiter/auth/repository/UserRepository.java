package com.recruiter.auth.repository;



import com.recruiter.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;


public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);



    boolean existsByUsername(String username);


    @Query("SELECT u FROM User u WHERE LOWER(u.username) LIKE %:query% AND u.role = :role")
    List<User> findByUsernameContainingAndRole(@Param("query") String query, @Param("role") String role);


    User findByEmail(String email);
}
