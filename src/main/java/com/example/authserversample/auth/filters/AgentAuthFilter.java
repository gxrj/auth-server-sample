package com.example.authserversample.auth.filters;

import com.example.authserversample.auth.models.AgentCredentials;
import com.example.authserversample.auth.tokens.AgentAuthToken;
import com.example.authserversample.utils.RequestHandler;
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

public class AgentAuthFilter extends AbstractAuthenticationProcessingFilter {

    public AgentAuthFilter( RequestMatcher matcher, AuthenticationManager authManager ) {
        super( matcher, authManager );
    }

    @Override
    public Authentication attemptAuthentication ( HttpServletRequest request, HttpServletResponse response )
    throws AuthenticationException, IOException, ServletException {

        var username = RequestHandler.obtainParam( request, "username" );
        var cpf = RequestHandler.obtainParam( request, "cpf" );
        var password = RequestHandler.obtainParam( request, "password" );

        AgentCredentials credentials = new AgentCredentials( cpf, password );
        var token = new AgentAuthToken( username, credentials );
        
        return getAuthenticationManager().authenticate( token );
    }
}