package ru.vas.apigateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.vas.apigateway.jwt.JwtClaimsConfig;
import ru.vas.apigateway.jwt.JwtUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
@Component
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {
    private final JwtUtils jwtUtils;
    private final JwtClaimsConfig jwtClaimsConfig;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            jwtUtils.getToken(request)
                    .flatMap(jwtUtils::getClaims)
                    .ifPresent(claims -> {
                        final String login = claims.get(jwtClaimsConfig.getLoginKey(), String.class);
                        final String authorities = claims.get(jwtClaimsConfig.getAuthoritiesKey(), String.class);
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                login, null, AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    });
        } catch (Exception ex) {
            log.error("JwtTokenAuthenticationFilter error", ex);
            SecurityContextHolder.clearContext();
        }
        filterChain.doFilter(request, response);
    }
}
