package com.example.authserversample.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity( debug = true )
@Configuration
public class AppSecurityConfig {

    @Bean
    @Order( 1 )
    SecurityFilterChain userSecurityFilterChain( final HttpSecurity http )
    throws Exception 
    {
        http
        .authorizeHttpRequests(
            authRequests -> authRequests.mvcMatchers( "/login" ).permitAll()
                                .anyRequest().authenticated()
        )
        .cors().disable()
        .sessionManagement()
                .sessionCreationPolicy( SessionCreationPolicy.NEVER )
        .and()
        .formLogin().loginPage( "/login" );

        return http.build();
    }

    @Bean
    @Order( 2 )
    SecurityFilterChain agentSecurityFilterChain( final HttpSecurity http )
            throws Exception
    {
        http
                .authorizeHttpRequests(
                        authRequests -> authRequests.mvcMatchers( "/agent/login" ).permitAll()
                                .anyRequest().authenticated()
                )
                .cors().disable()
                .sessionManagement()
                .sessionCreationPolicy( SessionCreationPolicy.NEVER )
                .and()
                .formLogin().loginPage( "/login-agent" );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user = User.builder()
                                .authorities( List.of() )
                                .username( "user" )
                                .password( encoder().encode( "123" ) )
                                .roles( "USER" )
                                .build();

        return new InMemoryUserDetailsManager( user );
    }

    @Bean
    public PasswordEncoder encoder() { return new BCryptPasswordEncoder(); }

}