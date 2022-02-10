package com.example.authserversample.utils;

import com.fasterxml.jackson.databind.JsonNode;

import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import java.io.IOException;

public class RequestHandler {

    public static JsonNode parseIntoJson( HttpServletRequest req )
            throws IOException {

        Assert.isTrue( isJsonContent( req ), "content-type cannot be handled as json" );

        var requestBody = cacheRequest( req ).getReader();
        var objMapper = Jackson2ObjectMapperBuilder.json().build();

        return  objMapper.readTree( requestBody );
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
        
        var contentType = req.getContentType();

        if( contentType == null )
            contentType = "application/octet-stream";

        return contentType.toLowerCase();
    }
}
