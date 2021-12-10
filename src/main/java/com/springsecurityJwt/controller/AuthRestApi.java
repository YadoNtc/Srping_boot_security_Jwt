package com.springsecurityJwt.controller;

import com.springsecurityJwt.Repository.RoleRepository;
import com.springsecurityJwt.Repository.UserRepository;
import com.springsecurityJwt.entity.Role;
import com.springsecurityJwt.entity.RoleName;
import com.springsecurityJwt.entity.User;
import com.springsecurityJwt.request.LoginForm;
import com.springsecurityJwt.request.SignupForm;
import com.springsecurityJwt.response.JwtResponse;
import com.springsecurityJwt.security.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestApi {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtProvider jwtProvider;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    RoleRepository roleRepository;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {

        // lay thong tin user tu request -> userDetailsServiceImpl
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUserName(),
                        loginRequest.getPassword()
                )
        );

        //Luu thông tin da xac thuc vao security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Tao token jwt
        String jwt = jwtProvider.generateJwtToken(authentication);

        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    @PostMapping("/signup")
    public ResponseEntity<String> registerUser(@Valid @RequestBody SignupForm signupRequest) {
        if (userRepository.existsByUserName(signupRequest.getUserName())) {
            return new ResponseEntity<String>("Fail: User name is already taken!",
                    HttpStatus.BAD_REQUEST);
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return new ResponseEntity<String>("Fail: email is already taken!",
                    HttpStatus.BAD_REQUEST);
        }

        // Create user's account
        User user = new User(signupRequest.getName(), signupRequest.getUserName(), signupRequest.getEmail(),
                passwordEncoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        strRoles.forEach(role -> {
            switch (role) {
                case "admin":
                    Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN);
                    if (adminRole == null) {
                        new RuntimeException("Fail: User role not find");
                    }
                    roles.add(adminRole);
                    break;
                case "pm":
                    Role pmRole = roleRepository.findByName(RoleName.ROLE_PM);
                    if (pmRole == null) {
                        new RuntimeException("Fail: User role not find");
                    }
                    roles.add(pmRole);
                    break;
                default:
                    Role userRole = roleRepository.findByName(RoleName.ROLE_USER);
                    if (userRole == null) {
                        new RuntimeException("Fail: User role not find");
                    }
                    roles.add(userRole);
            }
        });

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok().body("User registered successfully!");
    }

}
