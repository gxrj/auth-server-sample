package com.example.authserversample.config;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import com.example.authserversample.utils.KeyGenerator;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;


@Import( OAuth2AuthorizationServerConfiguration.class )
@Configuration( proxyBeanMethods = false )
public class AuthServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient client = RegisteredClient.withId( UUID.randomUUID().toString() )
                                .clientId( "client" )
                                .clientSecret( AppSecurityConfig.encoder().encode( "123" ) )
                                .clientAuthenticationMethod( ClientAuthenticationMethod.CLIENT_SECRET_BASIC )
                                .authorizationGrantType( AuthorizationGrantType.AUTHORIZATION_CODE )
                                .authorizationGrantType( AuthorizationGrantType.REFRESH_TOKEN )
                                .redirectUri( "http://localhost:8080/login" )
                                .scope( "test" )
                                .clientIdIssuedAt( Instant.now() )
                                .clientSettings(
                                        ClientSettings.builder()
                                                .requireAuthorizationConsent( false )
                                                .requireProofKey( false )
                                                .build()
                                )
                                .tokenSettings(
                                        TokenSettings.builder()
                                                .accessTokenTimeToLive( Duration.ofMinutes( 15 ) )
                                                .refreshTokenTimeToLive( Duration.ofMinutes( 15 ) )
                                                .build()
                                )
                                .clientName( "angular" )
                                .build();

        return new InMemoryRegisteredClientRepository( client );
    }

    @Bean
    public JwtDecoder JwtDecoder( JWKSource<SecurityContext> jwkSource ){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder( jwkSource );
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(){

        JWKSet keySet = new JWKSet( KeyGenerator.getECKeys() );
        return ( jwkSelector, context ) -> jwkSelector.select( keySet );
    }

    @Bean
    public ProviderSettings providerSettings(){
        return ProviderSettings.builder().issuer( "http://localhost:8080" ).build();
    }
}