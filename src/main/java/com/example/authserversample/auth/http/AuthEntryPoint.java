package com.example.authserversample.auth.http;

import lombok.NoArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@NoArgsConstructor

@Component
public class AuthEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence( HttpServletRequest req, HttpServletResponse resp, AuthenticationException ex )
    throws IOException, ServletException {

        String json = "{ \"status\": \"401\", \"message\": \" "+ex.getMessage()+" \" }";

        HttpHandler.setResponse( resp, HttpServletResponse.SC_UNAUTHORIZED, json );
    }
}