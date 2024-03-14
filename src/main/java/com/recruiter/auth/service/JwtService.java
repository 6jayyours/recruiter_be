package com.recruiter.auth.service;


import io.jsonwebtoken.Jwts;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import io.jsonwebtoken.Claims;
import java.util.function.Function;
import io.jsonwebtoken.io.Decoders;

@Service
public class JwtService {

    public JwtService(UserService userService) {
        this.userService = userService;
    }

    private UserService userService;


    private static final String SECRET_KEY = "dd307dd1f7e60eb498704935c0c6438a18700e0bcb1aea06cbd50f6e43d94593";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {

        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String generateToken(Map<String, Object> extratClaims, UserDetails userDetails) {

        String username = userDetails.getUsername();

        String userRole = userService.findRoleByUsername(username);
        Integer userId = userService.findIdByUsername(username);
        Map<String, Object> claims = new HashMap<>(extratClaims);
        claims.put("role", userRole);
        claims.put("userId", userId);

        return Jwts
                .builder()
                .setClaims(claims)
                .header()
                .add("typ", "JWT")
                .and()
                .claims(extratClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInKey())
                .compact();
    }
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
