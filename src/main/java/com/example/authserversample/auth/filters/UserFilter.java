package com.example.authserversample.auth.filters;

import com.example.authserversample.auth.http.HttpHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class UserFilter extends UsernamePasswordAuthenticationFilter {

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

            return new UsernamePasswordAuthenticationToken( username, password );
        }
        catch ( IOException ex ){ return null; }
    }
}