package com.example.authserversample.auth.http;

import lombok.NoArgsConstructor;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@NoArgsConstructor

@Component
public class AuthEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence( HttpServletRequest req, HttpServletResponse resp, AuthenticationException ex )
    throws IOException, ServletException {

        String json = "{ \n \"status\": \"401\", \n \"message\": \" acesse /oauth2/authorize \n\t\t client_id \n\t\t client_secret \n\t\t response_type=code \n\t\t redirect_uri \n\t\t scope \n\t\t state \n\t\t username \n\t\t password \" \n }";
        HttpHandler.setResponse( resp, HttpServletResponse.SC_UNAUTHORIZED, json );

    }
}