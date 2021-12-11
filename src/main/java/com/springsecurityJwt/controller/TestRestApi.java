package com.springsecurityJwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestRestApi {

    @GetMapping("/api/test/user")
    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'ROLE_ADMIN')")
    public String userAccess() {
        return ">> Thís is User's page";
    }

    @GetMapping("/api/test/pm")
    @PreAuthorize("hasAuthority('ROLE_PM')")
    public String pmAccess() {
        return ">>> Thís is PM's page";
    }

    @GetMapping("/api/test/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminAccess() {
        return ">>> Thís is Admin's page";
    }
}
