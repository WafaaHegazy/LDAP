package com.espark.adarsh.configuration.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.espark.adarsh.configuration.security.SecurityConfiguration;

@RestController
public class Restcontroller {

    @RequestMapping("/test")
    public Authentication hello() {
        return SecurityConfiguration.getAuthentication();
    }
}
