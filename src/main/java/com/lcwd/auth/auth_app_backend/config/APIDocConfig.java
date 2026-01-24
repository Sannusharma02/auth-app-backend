package com.lcwd.auth.auth_app_backend.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Auth Application",
                description = "Generic auth app that can be used with any application.",
                contact = @Contact(
                        name = "Sannu Sharma",
                        url = "https://github.com/Sannusharma02",
                        email = "sannusharma02@gmail.com"
                ),
                version = "1.0",
                summary = "This app is useful Auth app which can be used elsewhere for building webApp."
        ),
        security = {
                @SecurityRequirement(
                        name = "bearerAuth"
                )
        }
)

@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer", //Authorization: Bearer token
        bearerFormat = "JWT"
)
public class APIDocConfig {

}
