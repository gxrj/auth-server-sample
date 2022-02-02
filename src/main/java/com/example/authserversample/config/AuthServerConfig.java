package com.example.authserversample.config;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.example.authserversample.utils.KeyGenerator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;


@Import( OAuth2AuthorizationServerConfiguration.class )
@Configuration( proxyBeanMethods = false )
public class AuthServerConfig {

    @Value( "${address}" )
    private String address;

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        var userLoginPageUrl = address + "/login";
        var agentLoginPageUrl = address + "/agent/login" ;

        RegisteredClient client = RegisteredClient.withId( UUID.randomUUID().toString() )
                                .clientId( "client" )
                                .clientSecret( AppSecurityConfig.encoder().encode( "123" ) )
                                .clientAuthenticationMethod( ClientAuthenticationMethod.CLIENT_SECRET_POST )
                                .authorizationGrantType( AuthorizationGrantType.AUTHORIZATION_CODE )
                                .authorizationGrantType( AuthorizationGrantType.REFRESH_TOKEN )
                                .redirectUris( setConsumer -> setConsumer.addAll( Set.of( userLoginPageUrl, agentLoginPageUrl ) ) )
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
                                                .idTokenSignatureAlgorithm( SignatureAlgorithm.ES256 )
                                                .build()
                                )
                                .clientName( "angular" )
                                .build();

        return new InMemoryRegisteredClientRepository( client );
    }

    @Bean
    public JwtDecoder JwtDecoder( JWKSource<SecurityContext> jwkSource ) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder( jwkSource );
    }

    /* Implementation of JWKSource */
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, JOSEException {

        var signatureKeys = List.of( KeyGenerator.getEcJwk(), KeyGenerator.getRsaJwk() );
        JWKSet keySet = new JWKSet( signatureKeys );

        return ( jwkSelector, context ) -> jwkSelector.select( keySet );
    }

    /* Implementation of token customizer to set "alg" header to ES256 */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> context.getHeaders().algorithm( SignatureAlgorithm.ES256 );
    }

    @Bean
    public ProviderSettings providerSettings(){
        return ProviderSettings.builder().issuer( address ).build();
    }
}