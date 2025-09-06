package com.sidar.demo2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // React uygulamanızın çalıştığı portları ekleyin
        configuration.setAllowedOriginPatterns(Arrays.asList(
                "http://localhost:3000",  // React default port
                "http://localhost:3001",  // Alternative React port
                "http://127.0.0.1:3000",
                "http://127.0.0.1:3001"
        ));

        // İzin verilen HTTP metodları
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"
        ));

        // İzin verilen header'lar
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Cache-Control",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
        ));

        // Credentials (cookies, authorization headers) göndermeye izin ver
        configuration.setAllowCredentials(true);

        // Preflight cache süresi (dakika)
        configuration.setMaxAge(3600L);

        // Exposed headers (frontend'in okuyabileceği header'lar)
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Disposition"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public CorsFilter corsFilter() {
        return new CorsFilter(corsConfigurationSource());
    }
}