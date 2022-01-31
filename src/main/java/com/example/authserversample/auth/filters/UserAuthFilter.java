package com.example.authserversample.auth.filters;

import com.example.authserversample.auth.tokens.UserAuthToken;
import com.example.authserversample.utils.RequestHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class UserAuthFilter extends AbstractAuthenticationProcessingFilter {

    public UserAuthFilter( RequestMatcher matcher, AuthenticationManager authManager  ){
        super( matcher, authManager );
        setAuthenticationFailureHandler( this::unsuccessfulAuthentication );
    }

    @Override
    public Authentication attemptAuthentication( HttpServletRequest request, HttpServletResponse response )
    throws AuthenticationException, IOException, ServletException {

        var username = RequestHandler.obtainParam( request, "username" );
        var password = RequestHandler.obtainParam( request, "password" );

        var token = new UserAuthToken( username, password );

        return getAuthenticationManager().authenticate( token );
    }
}