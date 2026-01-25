package com.lcwd.auth.auth_app_backend.auth.services;

import jakarta.servlet.http.HttpServletResponse;

public interface CookieService {

    void attachRefreshCookie(HttpServletResponse response, String value, int maxAge);

    void clearRefreshCookie(HttpServletResponse response);

    void addNoStoreHeaders(HttpServletResponse response);

}

