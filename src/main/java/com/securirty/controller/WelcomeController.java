package com.securirty.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {

    @GetMapping("/welcome")
    public String welcomeMsg(){

        return "Welcome to the Basic Security App!";

    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint(){

        return "Hello, user..!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint(){

        return "Hello, admin..!";
    }

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @GetMapping("/user/admin")
    public String usrAdmindminEndpoint(){

        return "Hello,User and admin..!";
    }

}
