package ru.vas.apigateway.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt.claims.key")
@Data
public class JwtClaimsConfig {
    private String loginKey;
    private String authoritiesKey;
}
