package com.example.authserversample.auth.providers;

import com.example.authserversample.auth.models.AgentCredentials;
import com.example.authserversample.auth.tokens.AgentAuthToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class AgentAuthProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userService;

    @Autowired
    private PasswordEncoder encoder;

    @Override
    public Authentication authenticate( Authentication auth )
    throws AuthenticationException {

        // Get UserDetailsService ( this will change to a proper service )
        // Get PasswordEncoder
        // Check Parity
        // return or throw auth results

        var username = auth.getName();
        var agentCredentials = ( AgentCredentials ) auth.getCredentials();

        var user = userService.loadUserByUsername( username );
        var passwordMatches = encoder.matches( agentCredentials.getPassword(), user.getPassword() );

        if( passwordMatches )
            return new AgentAuthToken( username, agentCredentials, user.getAuthorities() );
        else
            throw new BadCredentialsException( "Bad credentials" );
    }

    @Override
    public boolean supports( Class< ? > authToken ) {
        return authToken.isInstance( AgentAuthToken.class );
    }
}