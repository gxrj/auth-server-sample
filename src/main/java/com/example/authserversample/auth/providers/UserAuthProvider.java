package com.example.authserversample.auth.providers;

import com.example.authserversample.auth.tokens.UserAuthToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;

public class UserAuthProvider implements AuthenticationProvider {

    public Authentication authenticate( Authentication auth ) {
        // Get UserDetails
        // Get PasswordEncoder
        // Check Parity
        return auth;
    }

    public boolean supports( Class< ? > authToken ) {
        return authToken.isInstance( UserAuthToken.class );
    }
}