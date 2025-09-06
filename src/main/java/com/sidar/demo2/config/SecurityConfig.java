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
                        // Public endpoints
                        .requestMatchers("/api/auth/**").permitAll()

                        // 🎯 GEÇİCİ ÇÖZÜBirilirli rolleri açıkça belirt
                        .requestMatchers(HttpMethod.GET, "/api/books/**")
                        .hasAnyRole("USER", "LIBRARIAN", "ADMIN", "SUPER_ADMIN")

                        .requestMatchers(HttpMethod.POST, "/api/books/**")
                        .hasAnyRole("LIBRARIAN", "ADMIN", "SUPER_ADMIN")

                        .requestMatchers(HttpMethod.PUT, "/api/books/**")
                        .hasAnyRole("LIBRARIAN", "ADMIN", "SUPER_ADMIN")

                        .requestMatchers(HttpMethod.DELETE, "/api/books/**")
                        .hasAnyRole("LIBRARIAN", "ADMIN", "SUPER_ADMIN")

                        // Admin endpoints - SUPER_ADMIN'i de ekle!
                        .requestMatchers("/api/admin/**")
                        .hasAnyRole("ADMIN", "SUPER_ADMIN") // ✅ Burada SUPER_ADMIN eklendi

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