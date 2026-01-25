package com.lcwd.auth.auth_app_backend.auth.config;

public class AppConstants {
    public static final String[] AUTH_PUBLIC_URLS = {
            "/api/v1/auth/**",
            "/v3/api-docs/**",
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/chat/**"
    };

    public static final String[] AUTH_ADMIN_URLS = {
            "/api/v1/users/**"
    };

    public static final String[] AUTH_GUEST_URLS = {
            "/chat/**"
    };

    public static final String ADMIN_ROLE = "ADMIN";
    public static final String GUEST_ROLE = "GUEST";
}
