package com.example.authserversample.auth.controllers;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller

@RequestMapping( produces = MediaType.ALL_VALUE )
public class LoginController {
    
    @GetMapping( path = "/login" )
    public String getForm(){
        return "login";
    }

    @GetMapping( path = "/agent/login" )
    public String getAgentForm(){
        return "login-agent";
    }
}
