package com.thesystemsmith.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class APISecurityConfig {

    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager jUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        jUserDetailsManager.setUsersByUsernameQuery("SELECT user_id, password, active FROM Users WHERE user_id = ?;");

        jUserDetailsManager.setAuthoritiesByUsernameQuery("SELECT user_id, role FROM Roles WHERE user_id = ?;");

        return jUserDetailsManager;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                configurer -> configurer.requestMatchers(HttpMethod.GET,
                                "/dashboard")
                        .hasRole("ADMIN"));

        http.httpBasic(Customizer.withDefaults());

        return http.build();
    }
}