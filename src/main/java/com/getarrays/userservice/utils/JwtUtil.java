package com.getarrays.userservice.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.getarrays.userservice.domain.Role;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@Slf4j
public class JwtUtil {


     public static final Algorithm JWT_ALGORITHM = Algorithm.HMAC256("jwtSecret".getBytes());


    public DecodedJWT verifyAndGetDecodedJwt(String authorizationHeader) {
        String token = authorizationHeader.substring("Bearer ".length());
        Algorithm algorithm = JWT_ALGORITHM;
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        return decodedJWT;

    }

    public String getAccessToken(User user, HttpServletRequest request) {
        return JwtCommonBase(user, request)
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(JWT_ALGORITHM);
    }

    public String getRefreshToken(User user, HttpServletRequest request) {
       return JwtCommonBase(user, request)
                .sign(JWT_ALGORITHM);
    }

    public String getRefreshTokenWithRoles(com.getarrays.userservice.domain.User appUser, HttpServletRequest request) {
       return JwtCommonBase(appUser, request)
               .withClaim("roles", appUser.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .sign(JWT_ALGORITHM);
    }

    public JWTCreator.Builder JwtCommonBase(User user, HttpServletRequest request) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000)) // 30min pour access et refresh token
                .withIssuer(request.getRequestURL().toString());
    }
    public JWTCreator.Builder JwtCommonBase(com.getarrays.userservice.domain.User appUser, HttpServletRequest request) {
        return JWT.create()
                .withSubject(appUser.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000)) // 30min pour access et refresh token
                .withIssuer(request.getRequestURL().toString());
    }





}
