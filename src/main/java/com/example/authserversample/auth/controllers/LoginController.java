package com.example.authserversample.auth.controllers;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller

@RequestMapping(
        consumes = MediaType.ALL_VALUE,
        produces = MediaType.ALL_VALUE )
public class LoginController {

    @RequestMapping( path = "/login" )
    public String getForm(){ return "login"; }

    @GetMapping( path = "/agent/login" )
    public String getAgentForm(){ return "login-agent"; }
        
    @GetMapping( path = "/error" )
    public String getErrorPage() { return "error"; }  

    @GetMapping( path = "/unauthorized" )
    public String getUnauthorizedPage() { return "unauthorized"; }
}
