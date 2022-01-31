package com.example.authserversample.utils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ResponseHandler {

    public static void prepareJsonResponse( HttpServletResponse resp,
                                            int httpStatus, String message )
    throws IOException {

        resp.setContentType( "application/json" );
        resp.setCharacterEncoding( "utf-8" );

        resp.getWriter().print( "{ \"message\": \" "+ message +" \" }" );
        resp.setStatus( httpStatus );
    }
}
