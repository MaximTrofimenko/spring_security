package com.trofimenko.springsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    public String createToken(String username,String role){
        Claims claims = Jwts.claims().setSubject(username);

        return null;
    }
}
