package com.securirty.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securirty.jwt.JwtUtils;
import com.securirty.jwt.LogInRequest;
import com.securirty.jwt.LogInResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class WelcomeController {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/welcome")
    public String welcomeMsg() {

        return "Welcome to the Basic Security App!";

    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint() {

        return "Hello, user..!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {

        return "Hello, admin..!";
    }

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @GetMapping("/user/admin")
    public String usrAdminEndpoint() {

        return "Hello,User and admin..!";
    }

    @PostMapping("/token")
    public ResponseEntity<?> authenticationUser(@RequestBody LogInRequest logInRequest) {

        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate
                    (new UsernamePasswordAuthenticationToken(logInRequest.getUsername(), logInRequest.getPassword()));
        } catch (AuthenticationException e) {

            final Map<String, Object> body = new HashMap<>();

            body.put("status", false);
            body.put("message", "Bad Credentials");
            return new ResponseEntity<>(body, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUserName(userDetails);

        List<String> roleList = userDetails.getAuthorities().stream().map(role -> role.getAuthority()).collect(Collectors.toList());

        LogInResponse logInResponse= new LogInResponse(jwtToken,userDetails.getUsername(),roleList);

        return ResponseEntity.ok(logInResponse);


    }

}
