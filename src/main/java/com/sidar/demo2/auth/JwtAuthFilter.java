package com.sidar.demo2.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        final String requestURI = request.getRequestURI();

        log.debug("Processing request: {} {}", request.getMethod(), requestURI);

        // Public endpoint kontrolü - Token gerektirmez
        if (requestURI.startsWith("/api/auth/")) {
            log.debug("Public endpoint accessed: {}", requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        // Bearer token kontrolü
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("No Bearer token found for protected endpoint: {}", requestURI);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Authentication required\", \"path\": \"" + requestURI + "\"}");
            return;
        }

        // "Bearer " kısmını çıkar, sadece token'ı al
        jwt = authHeader.substring(7);
        log.debug("JWT token extracted, length: {}", jwt.length());

        try {
            // Token'dan username çıkar
            username = jwtUtil.extractUsername(jwt);
            log.debug("Username extracted from token: {}", username);

            // Username varsa ve daha önce authenticate olmamışsa
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // User details yükle
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                log.debug("UserDetails loaded for user: {}, authorities: {}",
                        username, userDetails.getAuthorities());

                // Token geçerliyse authentication'ı context'e ekle
                if (jwtUtil.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("Authentication set in SecurityContext for user: {} with authorities: {}",
                            username, userDetails.getAuthorities());
                } else {
                    log.warn("Invalid token for user: {}", username);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Invalid token\"}");
                    return;
                }
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication: ", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Authentication failed: " + e.getMessage() + "\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}