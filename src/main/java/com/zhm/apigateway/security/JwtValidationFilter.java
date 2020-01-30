package com.zhm.apigateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@Component
public class JwtValidationFilter extends OncePerRequestFilter {

    private Environment env;

    @Autowired
    public JwtValidationFilter(Environment env) {
        this.env = env;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        // reading the authorization header from the request, this will contain our jwt token
        String authHeader = req.getHeader("Authorization");

        // if header start with Bearer, meaning it is a jwt token
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // extract the Bearer and obtain only the jwt token
            String jwtToken = authHeader.substring(7);
            // extract the info from from jwt token. parse will fail if token expires
            Jws<Claims> claims = Jwts.parser()
                    .setSigningKey(env.getProperty("token.secret"))
                    .parseClaimsJws(jwtToken);
            String userId = claims.getBody().getSubject();
            // List<String> roles = claims.getBody().get("roles", List.class);
            if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        // carry on to the next filter
        chain.doFilter(req, res);
    }
}
