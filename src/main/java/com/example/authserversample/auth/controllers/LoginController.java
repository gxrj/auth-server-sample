package com.example.authserversample.auth.controllers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller

@RequestMapping(
        consumes = MediaType.ALL_VALUE,
        produces = MediaType.ALL_VALUE )
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
