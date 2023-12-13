package com.example.jwtspring.controller;

import com.example.jwtspring.entity.JwtToken;
import com.example.jwtspring.entity.UserSign;
import com.example.jwtspring.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RequestMapping("/user")
@RestController
public class UserController {

    private final UserService userService;

    // https://suddiyo.tistory.com/entry/Spring-Spring-Security-JWT-%EB%A1%9C%EA%B7%B8%EC%9D%B8-%EA%B5%AC%ED%98%84%ED%95%98%EA%B8%B0-2
    @PostMapping("/sign-in")
    public ResponseEntity<JwtToken> signIn(@RequestBody UserSign userSign) {
        String signId = userSign.getSignId();
        String password = userSign.getPassword();
        System.out.println("###### 3");
        return ResponseEntity.ok(this.userService.signIn(signId, password));
    }
}
