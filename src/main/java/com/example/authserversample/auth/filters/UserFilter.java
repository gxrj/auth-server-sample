package com.example.authserversample.auth.filters;

import com.example.authserversample.auth.http.HttpHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class UserFilter extends UsernamePasswordAuthenticationFilter {

    private final Logger log = LoggerFactory.getLogger( UserFilter.class );

    @Override
    public Authentication attemptAuthentication( HttpServletRequest req, HttpServletResponse resp )
            throws AuthenticationException{

        if( !req.getMethod().equals( "POST" ) ) {
            throw new AuthenticationServiceException("Metodo nao suportado:" + req.getMethod());
        }

        try {
            var json = HttpHandler.parseIntoJsonNode( req );

            var username = json.get( "username" ).asText();
            var password = json.get( "password" ).asText();
            var token = new UsernamePasswordAuthenticationToken( username, password );

            log.info("@@@@@@@@@@@@@@@ : "+username);

            return this.getAuthenticationManager().authenticate( token );
        }
        catch ( IOException ex ){
            log.info( "@@@@@@@@@@@@@@@ : "+ex.getMessage() );
            return null;
        }
    }
}