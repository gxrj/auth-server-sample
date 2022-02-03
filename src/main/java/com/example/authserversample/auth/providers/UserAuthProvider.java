package com.example.authserversample.auth.providers;

import com.example.authserversample.auth.tokens.UserAuthToken;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@AllArgsConstructor
public class UserAuthProvider implements AuthenticationProvider {

    private UserDetailsService userService;
    private PasswordEncoder encoder;

    @Override
    public Authentication authenticate( Authentication auth )
    throws AuthenticationException {

        // Get UserDetailsService ( this will change to a proper service )
        // Get PasswordEncoder
        // Check Parity
        // return or throw auth results

        var username = auth.getName();
        var password = auth.getCredentials().toString();

        var user = userService.loadUserByUsername( username );
        var passwordMatches = encoder.matches( password, user.getPassword() );

        if( passwordMatches )
            return new UserAuthToken( user.getUsername(), user.getPassword(),
                                      user.getAuthorities() );
        else
            throw new BadCredentialsException( "Bad credentials" );
    }

    @Override
    public boolean supports( Class< ? > authToken ) {
        return authToken.equals( UserAuthToken.class );
    }
}