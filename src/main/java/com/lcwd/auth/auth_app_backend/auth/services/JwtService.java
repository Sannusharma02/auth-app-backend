package com.lcwd.auth.auth_app_backend.auth.services;

import com.lcwd.auth.auth_app_backend.auth.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import java.util.UUID;

public interface JwtService {

    String generateToken(User user);

    String generateRefreshToken(User user, String jti);

    Jws<Claims> parse(String token);

    boolean isAccessToken(String token);
    boolean isRefreshToken(String token);

    UUID getUserId(String token);
    String getJti(String token);

}
