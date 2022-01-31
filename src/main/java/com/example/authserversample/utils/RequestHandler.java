package com.example.authserversample.utils;

import com.fasterxml.jackson.databind.JsonNode;

import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

public class RequestHandler {

    public static String obtainParam( HttpServletRequest req, String param )
            throws IOException {

        var isHttpPost = req.getMethod().equalsIgnoreCase( "POST" );

        if( isHttpPost && RequestHandler.isJsonContent( req ) ) {

            var json = RequestHandler.parseIntoJson( req );
            Assert.notNull( json, "error while parsing into json" );

            var result = json.get( param ).asText();
            Assert.notNull( result, "param name not found" );

            return result;
        }

        return req.getParameter( param );
    }

    public static JsonNode parseIntoJson( HttpServletRequest req )
            throws IOException {

        Assert.isTrue( isJsonContent( req ), "content-type cannot be handled as json" );

        var requestBody = cacheRequest( req ).getReader();
        var ObjectMapper = Jackson2ObjectMapperBuilder.json().build();

        return  ObjectMapper.readTree( requestBody );
    }

    public static boolean isJsonContent( HttpServletRequest req ){
        return checkRequestType( req ).equals( "application/json" );
    }

    public static String checkRequestType( HttpServletRequest req ){
        var contentType = req.getContentType();
        Assert.notNull( contentType, "content-type not known" );

        return contentType.toLowerCase();
    }

    private static HttpServletRequestWrapper cacheRequest( HttpServletRequest req ) {
        Assert.notNull( req, "cacheRequest() cannot handle null objects" );
        return new HttpServletRequestWrapper( req );
    }
}
