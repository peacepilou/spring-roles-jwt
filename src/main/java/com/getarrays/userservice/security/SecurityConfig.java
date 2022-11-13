package com.getarrays.userservice.security;

import com.getarrays.userservice.domain.ERole;
import com.getarrays.userservice.filter.CustomAuthenticationFilter;
import com.getarrays.userservice.filter.JwtTokenFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors();
        http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests()
                .antMatchers("/login", "/api/token/refresh").permitAll()
                .antMatchers(GET, "/api/users").hasRole(ERole.USER.name())
                .antMatchers(POST, "/api/user/save/**").hasRole(ERole.ADMIN.name())
                .antMatchers(GET, "/api/for-user").hasRole(ERole.USER.name())
                .antMatchers(GET, "/api/for-manager").hasRole(ERole.MANAGER.name())
                .antMatchers(GET, "/api/for-admin").hasRole(ERole.ADMIN.name())
                .anyRequest().authenticated();



        http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));
        // On veut vérifier le JWT avant de faire quoi que ce soit, d'où le "before"
         http.addFilterBefore(new JwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    // Il nous faut accéder à l'authentification manager. Par défaut, ce n'est pas public accessible.
    // On expose donc explicitement notre bean ici.
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


}
