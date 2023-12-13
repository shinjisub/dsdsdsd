package com.example.jwtspring.service;

import com.example.jwtspring.entity.JwtToken;
import com.example.jwtspring.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserService {

    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public JwtToken signIn(String signId, String password) {
        System.out.println("###### 4");
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(signId, password);
        Authentication authenticate = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        JwtToken jwtToken = this.jwtTokenProvider.generateToken(authenticate);
        return jwtToken;
    }
}
