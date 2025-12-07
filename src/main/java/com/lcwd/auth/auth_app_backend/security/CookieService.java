package com.lcwd.auth.auth_app_backend.security;

import org.springframework.stereotype.Service;

@Service
public class CookieService {

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
//    private final int cookieMaxAge;
    private final String cookieDomain;
    private final String cookieSameSite;

    public CookieService(String refreshTokenCookieName, boolean cookieHttpOnly, boolean cookieSecure, String cookieDomain, String cookieSameSite) {
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieDomain = cookieDomain;
        this.cookieSameSite = cookieSameSite;
    }
}
