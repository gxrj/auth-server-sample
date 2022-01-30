package com.example.authserversample.auth.providers;

import com.example.authserversample.auth.tokens.AgentAuthToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;

public class AgentAuthProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate( Authentication auth ) {
        // Get UserDetails
        // Get PasswordEncoder
        // Check Parity
        return auth;
    }

    @Override
    public boolean supports( Class< ? > authToken ) {
        return authToken.isInstance( AgentAuthToken.class );
    }
}