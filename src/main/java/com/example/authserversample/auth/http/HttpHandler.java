package com.example.authserversample.auth.http;

import com.fasterxml.jackson.databind.JsonNode;

import lombok.NoArgsConstructor;

import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.validation.constraints.NotNull;

import java.io.IOException;


@NoArgsConstructor

@Component
public class HttpHandler
        implements AccessDeniedHandler, AuthenticationFailureHandler, AuthenticationSuccessHandler,
        LogoutSuccessHandler {

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest req, HttpServletResponse resp, AuthenticationException authEx )
            throws IOException, ServletException {
        String json = "{ \"status\": \"401\", \"message\": \"Nao autenticado\" }";

        HttpHandler.setResponse( resp, HttpServletResponse.SC_UNAUTHORIZED, json );
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest req, HttpServletResponse resp, Authentication auth )
            throws IOException, ServletException {

        String json = "{ \"status\": \"202\", \"message\": \"Bem vindo\" }";

        HttpHandler.setResponse( resp, HttpServletResponse.SC_ACCEPTED, json );
    }

    @Override
    public void handle(
            HttpServletRequest req, HttpServletResponse resp, AccessDeniedException ex )
            throws IOException, ServletException {

        String json = "{ \"status\": \"403\", \"message\": \"Acesso nao autorizado\" }";

        HttpHandler.setResponse( resp, HttpServletResponse.SC_FORBIDDEN, json );
    }

    @Override
    public void onLogoutSuccess(
            HttpServletRequest req, HttpServletResponse resp, Authentication auth )
            throws  IOException, ServletException {

        String json = "{ \"status\": \"202\", \"message\": \"Sessao finalizada\" }";

        HttpHandler.setResponse( resp, HttpServletResponse.SC_ACCEPTED, json );
    }

    public static void setResponse( HttpServletResponse resp, int status, String json )
            throws IOException, ServletException {

        resp.setContentType( "application/json" );
        resp.setCharacterEncoding( "utf-8" );

        resp.getWriter().print( json );
        resp.setStatus( status );
    }

    public static JsonNode parseIntoJsonNode( HttpServletRequest req ) throws IOException {

        var wrapper = copyRequest( req );
        var requestBody = wrapper.getReader();
        var objectMapper = Jackson2ObjectMapperBuilder.json().build();

        return objectMapper.readTree( requestBody );
    }

    @NotNull
    private static HttpServletRequestWrapper copyRequest( HttpServletRequest req ) {
        return new HttpServletRequestWrapper( req );
    }
}