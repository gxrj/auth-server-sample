package com.example.authserversample.auth.filters;

import com.example.authserversample.auth.tokens.UserAuthToken;
import com.example.authserversample.utils.RequestHandler;
import com.example.authserversample.utils.ResponseHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class UserAuthFilter extends AbstractAuthenticationProcessingFilter {

    private final Log log = LogFactory.getLog( getClass() );

    public UserAuthFilter( RequestMatcher matcher, AuthenticationManager authManager  ){
        super( matcher, authManager );

        setAuthenticationFailureHandler(
                ( req, resp, authEx ) -> ResponseHandler
                                            .prepareJsonResponse( resp, 400, "Bad request" ) );
    }

    @Override
    public Authentication attemptAuthentication( HttpServletRequest request, HttpServletResponse response )
    throws AuthenticationException, IOException, ServletException {
        log.debug( "Attempting authentication from:" + getClass().getName() );
        var username = RequestHandler.obtainParam( request, "username" );
        var password = RequestHandler.obtainParam( request, "password" );

        var token = new UserAuthToken( username, password );

        log.debug( "Authentication extracted id: "+username );

        return getAuthenticationManager().authenticate( token );
    }
}