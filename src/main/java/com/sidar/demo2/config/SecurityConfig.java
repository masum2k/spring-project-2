package com.sidar.demo2.config;

import com.sidar.demo2.auth.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints - Authentication gerektirmez
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/error").permitAll()

                        // Book endpoints - GET tüm authenticated user'lar için
                        .requestMatchers(HttpMethod.GET, "/api/books/**")
                        .hasAnyRole("USER", "LIBRARIAN", "ADMIN", "SUPER_ADMIN")

                        // Book CRUD operations - sadece yetkili kullanıcılar
                        .requestMatchers(HttpMethod.POST, "/api/books/**")
                        .hasAnyRole("LIBRARIAN", "ADMIN", "SUPER_ADMIN")

                        .requestMatchers(HttpMethod.PUT, "/api/books/**")
                        .hasAnyRole("LIBRARIAN", "ADMIN", "SUPER_ADMIN")

                        .requestMatchers(HttpMethod.DELETE, "/api/books/**")
                        .hasAnyRole("LIBRARIAN", "ADMIN", "SUPER_ADMIN")

                        // Admin endpoints - ADMIN ve SUPER_ADMIN erişebilir
                        .requestMatchers("/api/admin/**")
                        .hasAnyRole("ADMIN", "SUPER_ADMIN")

                        // Diğer tüm endpoint'ler authentication gerektirir
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}