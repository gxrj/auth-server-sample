package com.example.authserversample.config;

import java.util.List;

import com.example.authserversample.auth.filters.UserFilter;
import com.example.authserversample.auth.http.AuthEntryPoint;
import com.example.authserversample.auth.http.HttpHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity( debug = true )
@Configuration
public class AppSecurityConfig {

    @Autowired
    private HttpHandler httpHandler;

    @Autowired
    private AuthEntryPoint authEntryPoint;

    @Bean
    SecurityFilterChain securityFilterChain( HttpSecurity http )
    throws Exception 
    {
        http
        .authorizeHttpRequests(
            authRequests -> authRequests.anyRequest().authenticated()
        )
        .csrf().disable()
        .requestCache().disable()
        .exceptionHandling()
                .authenticationEntryPoint( authEntryPoint )
                .accessDeniedHandler( httpHandler )
        .and()
        .formLogin()
                .successHandler( httpHandler )
                .failureHandler( httpHandler )
        .and()
        .logout()
                .logoutSuccessHandler( httpHandler )
        .and()
        .addFilterAt( new UserFilter(), UsernamePasswordAuthenticationFilter.class );

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

    @Bean
    public AuthenticationManager authenticationManager( AuthenticationManagerBuilder builder ){
        return builder.getOrBuild();
    }
}