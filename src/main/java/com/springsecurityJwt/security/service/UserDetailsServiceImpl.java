package com.springsecurityJwt.security.service;

import com.springsecurityJwt.Repository.UserRepository;
import com.springsecurityJwt.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository repo;

    // Lay thong tin user tu db theo username -> UserDetailImpl class
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repo.findByUserName(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with -> username or email: " + username));

        return new UserDetailsImpl(user);
    }
}
