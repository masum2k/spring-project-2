package com.sidar.demo2.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

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

        // Authorization header'ından JWT token'ı al
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        final String requestURI = request.getRequestURI();

        // Public endpoint kontrolü - Token gerektirmez
        if (requestURI.startsWith("/api/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Bearer token kontrolü
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // Token yoksa tüm protected endpoint'ler için 401 döndür
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Authentication required\"}");
            return; // ✅ Burada dur - filterChain.doFilter() çağırma!
        }

        // "Bearer " kısmını çıkar, sadece token'ı al
        jwt = authHeader.substring(7);

        try {
            // Token'dan username çıkar
            username = jwtUtil.extractUsername(jwt);

            // Username varsa ve daha önce authenticate olmamışsa
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // User details yükle
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                // Token geçerliyse authentication'ı context'e ekle
                if (jwtUtil.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                } else {
                    // Token geçersizse 401 döndür
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Invalid token\"}");
                    return;
                }
            }
        } catch (Exception e) {
            // Token parse edilemezse 401 döndür
            logger.error("Cannot set user authentication: {}", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Authentication failed\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}