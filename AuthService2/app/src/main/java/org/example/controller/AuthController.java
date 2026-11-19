package org.example.controller;

import lombok.AllArgsConstructor;
import org.example.entities.RefreshToken;
import org.example.model.UserInfoDto;
import org.example.response.JwtResponseDto;
import org.example.service.JwtService;
import org.example.service.RefreshTokenService;
import org.example.service.UserDetailServiceimp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@AllArgsConstructor
@RestController
public class AuthController {
    @Autowired
    private JwtService jwtService;

    @Autowired
    private RefreshTokenService refreshTokenService;;

    @Autowired
    private UserDetailServiceimp userDetailServiceimp;

    @PostMapping("auth/v1/signup")
    public ResponseEntity signUp(@RequestBody UserInfoDto userInfoDto) {
            try{
                Boolean isSignedUp=userDetailServiceimp.signupUser(userInfoDto);
                if(Boolean.FALSE.equals(isSignedUp)){
                    return new ResponseEntity<>("already exists", HttpStatus.BAD_REQUEST);
                }
                RefreshToken refreshToken=refreshTokenService.createRefreshToken(userInfoDto.getUserName());
                String jwtToken=jwtService.createToken(new HashMap<>(),userInfoDto.getUserName());
                return new ResponseEntity<>(JwtResponseDto.builder().accessToken(jwtToken).token(refreshToken.getToken()).build(),HttpStatus.OK);
            }catch(Exception e){
                return new ResponseEntity<>("exception in signup",HttpStatus.BAD_REQUEST);
            }
    }

}
