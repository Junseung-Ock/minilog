package com.asdf.minilog.config;

import com.asdf.minilog.security.JwtAuthenticationEntryPoint;
import com.asdf.minilog.security.JwtRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

  private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private JwtRequestFilter jwtRequestFilter;

  @Autowired
  public SecurityConfig(
      JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint, JwtRequestFilter jwtRequestFilter) {
    this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    this.jwtRequestFilter = jwtRequestFilter;
  }

  // 사용자의 비밀번호를 안전하게 암호화
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  // 인증 과정을 총괄
  @Bean
  public AuthenticationManager authenticationManagerBean(
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  // 인증 및 인가 절차를 순차적으로 수행
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .csrf(AbstractHttpConfigurer::disable)
        .authorizeRequests(
            (requests) ->
                requests
                    .requestMatchers("/api/v2/auth/login", "/swagger-ui/**", "/v3/api-docs/**")
                    .permitAll()
                    .requestMatchers(HttpMethod.POST, "/api/v2/user")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/v2/user/{userId}")
                    .permitAll()
                    .requestMatchers(HttpMethod.DELETE, "/api/v2/user/{userId}")
                    .hasRole("ADMIN")
                    .anyRequest()
                    .authenticated())
        .exceptionHandling(
            exceptionHandling ->
                exceptionHandling.authenticationEntryPoint(jwtAuthenticationEntryPoint))
        .sessionManagement(
            sessionManagement ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    // jwt 기반 인증을 기존 인증보다 먼저 수행하도록 함 (기존 인증은 필요한 경우에만 수행)
    httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    return httpSecurity.build();
  }
}
