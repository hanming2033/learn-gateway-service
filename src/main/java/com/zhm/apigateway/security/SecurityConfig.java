package com.zhm.apigateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private Environment env;
    private JwtValidationFilter jwtValidationFilter;

    @Autowired
    public SecurityConfig(Environment env, JwtValidationFilter jwtValidationFilter) {
        this.env = env;
        this.jwtValidationFilter = jwtValidationFilter;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.headers().frameOptions().disable();
        http.authorizeRequests()
                .antMatchers(env.getProperty("api.h2console.url")).permitAll() // allow h2 console
                .antMatchers(HttpMethod.POST, env.getProperty("api.login.url")).permitAll() // allow login
                .antMatchers(HttpMethod.POST, env.getProperty("api.register.url")).permitAll() // allow register
                .antMatchers(HttpMethod.GET, env.getProperty("api.ping.url")).permitAll() // allow public ping
                .anyRequest().authenticated()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // make application stateless
                .and().addFilterBefore(jwtValidationFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
