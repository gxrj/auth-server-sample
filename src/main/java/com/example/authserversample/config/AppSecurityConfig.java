package com.example.authserversample.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.example.authserversample.auth.filters.AgentAuthFilter;
import com.example.authserversample.auth.filters.UserAuthFilter;
import com.example.authserversample.auth.providers.AgentAuthProvider;
import com.example.authserversample.auth.providers.UserAuthProvider;

import org.springframework.context.annotation.Bean;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import org.springframework.security.web.SecurityFilterChain;

import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@EnableWebSecurity( debug = true )
public class AppSecurityConfig {

    // @formatter:off
    @Bean
    SecurityFilterChain appSecurityFilterChain( HttpSecurity http )
    throws Exception {

        http.authorizeHttpRequests(
            authRequests -> authRequests
                                .mvcMatchers( "/login", "/agent/login", "/css/**", "/img/**" )
                                .permitAll()
                                .anyRequest().authenticated()
        );

        http.cors().disable()
        .csrf( Customizer.withDefaults() )
        .sessionManagement()
                .sessionCreationPolicy( SessionCreationPolicy.NEVER );

        http
        .exceptionHandling()
                .defaultAuthenticationEntryPointFor( /* Login para usuários */
                        new LoginUrlAuthenticationEntryPoint( "/login" ),
                        new AntPathRequestMatcher("/login" )
                )
                .defaultAuthenticationEntryPointFor( /* Login para funionários públicos */
                        new LoginUrlAuthenticationEntryPoint( "/agent/login" ),
                        new AntPathRequestMatcher("/agent/login" )
                );

        http
        .addFilterBefore( /* Filtragem de funionários públicos */
                new AgentAuthFilter( requestMatcher( "/agent/login", "POST" ),
                                     authenticationManager()
                ),
                AnonymousAuthenticationFilter.class
        )
        .addFilterAfter( /* Filtragem de usuários */
                new UserAuthFilter( requestMatcher( "/login", "POST" ),
                                    authenticationManager()
                ),
                AgentAuthFilter.class
        );

        http.headers()
                .httpStrictTransportSecurity().disable();

        return http.build();
    }
    
    // @formatter:on
    private RequestMatcher requestMatcher( String pattern, String httpMethod ) {
        return new AntPathRequestMatcher( pattern, httpMethod );
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager( new AgentAuthProvider( userDetailsService(), encoder() ),
                                    new UserAuthProvider( userDetailsService(), encoder() ) );
    }

    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user = User.builder()
                .authorities( List.of() )
                .username( "user" )
                .password( encoder().encode( "123" ) )
                .roles( "USER" )
                .build();

        UserDetails agent = User.builder()
                .authorities( List.of() )
                .username( "agent" )
                .password( encoder().encode( "123" ) )
                .roles( "AGENT" )
                .build();

        return new InMemoryUserDetailsManager( user, agent );
    }

    @Bean
    public static PasswordEncoder encoder() {

        var defaultEncoder = "argon2";

        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put( "bcrypt", new BCryptPasswordEncoder() );
        encoders.put( "scrypt", new SCryptPasswordEncoder() );
        encoders.put( "argon2", new Argon2PasswordEncoder() );

        return new DelegatingPasswordEncoder( defaultEncoder, encoders );
    }
}
