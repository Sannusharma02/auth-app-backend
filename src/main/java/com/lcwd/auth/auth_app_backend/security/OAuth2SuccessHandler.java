package com.lcwd.auth.auth_app_backend.security;

import com.lcwd.auth.auth_app_backend.entities.RefreshToken;
import com.lcwd.auth.auth_app_backend.entities.User;
import com.lcwd.auth.auth_app_backend.enums.Provider;
import com.lcwd.auth.auth_app_backend.repositories.RefreshTokenRepository;
import com.lcwd.auth.auth_app_backend.repositories.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("{app.auth.frontend.success-redirect}")
    private String frontEndSuccessUrl;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        logger.info("Authentication success");
        logger.info(authentication.toString());
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        //identify user:

        String registrationId = "unknown";
        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        logger.info("registrationId:{}", registrationId);
        logger.info("username:{}", oAuth2User.getName());

        User user;
        switch (registrationId) {
            case "google" -> {
                String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
                String picture = oAuth2User.getAttributes().getOrDefault("picture", "").toString();
                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .enable(true)
                        .image(picture)
                        .provider(Provider.GOOGLE)
                        .build();

                user = userRepository.findByEmail(email).orElseGet( () -> userRepository.save(newUser));
            }

            case "github" -> {
                String name = oAuth2User.getAttributes().getOrDefault("login", "").toString();
//                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                String githubId = oAuth2User.getAttributes().getOrDefault("id", "").toString();
                String image = oAuth2User.getAttributes().getOrDefault("avatar_url", "").toString();

                String email = (String) oAuth2User.getAttributes().get("email");
                if ( email== null) {
                    email = name + "@github.com";
                }


                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(image)
                        .enable(true)
                        .provider(Provider.GITHUB)
                        .providerId(githubId)
                        .build();

                user = userRepository.findByEmail(email).orElseGet( () -> userRepository.save(newUser));

            }

            default -> {
                throw new RuntimeException("invalid registrationId");
            }
        }

        //username
        //user email
        //New User Create
        //Jwt Token ke sath front  -- pe fir redirect.
        // refresh token bana ke dunga

        //refresh

//        user--> refresh roken token

        String jti = UUID.randomUUID().toString();
        RefreshToken refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .build();

        refreshTokenRepository.save(refreshTokenOb);
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());
        cookieService.attachRefreshCookie(response,refreshToken, (int) jwtService.getRefreshTtlSeconds());
//        response.getWriter().write("Authentication success");
        response.sendRedirect(frontEndSuccessUrl);
    }
}
