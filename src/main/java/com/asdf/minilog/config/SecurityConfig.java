package com.asdf.minilog.config;

import com.asdf.minilog.security.JwtAuthenticationEntryPoint;
import com.asdf.minilog.security.JwtRequestFilter;
import com.asdf.minilog.security.OAuth2SuccessHandler;
import com.asdf.minilog.service.CustomOAuth2UserService;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

  private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private JwtRequestFilter jwtRequestFilter;

  // 추가된 OAuth2 관련 의존성
  private final CustomOAuth2UserService customOAuth2UserService;
  private final OAuth2SuccessHandler oAuth2SuccessHandler;

  @Autowired
  public SecurityConfig(
      JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
      JwtRequestFilter jwtRequestFilter,
      CustomOAuth2UserService customOAuth2UserService,
      OAuth2SuccessHandler oAuth2SuccessHandler) {
    this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    this.jwtRequestFilter = jwtRequestFilter;
    this.customOAuth2UserService = customOAuth2UserService;
    this.oAuth2SuccessHandler = oAuth2SuccessHandler;
  }

  // 인증 과정을 총괄
  @Bean
  public AuthenticationManager authenticationManagerBean(
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

  // 인증 및 인가 절차를 순차적으로 수행
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
      httpSecurity
              .csrf(AbstractHttpConfigurer::disable)
              // [추가] CORS 설정을 적용합니다.
              .cors(cors -> cors.configurationSource(corsConfigurationSource()))
              .authorizeHttpRequests( // authorizeRequests 대신 최근 문법인 authorizeHttpRequests 권장
                      (requests) ->
                              requests
                                      .requestMatchers(
                                              "/api/v2/auth/login",
                                              "/api/v2/auth/refresh",
                                              "/swagger-ui/**",
                                              "/v3/api-docs/**",
                                              "/login/oauth2/**",
                                              "/oauth2/**",
                                              "/favicon.ico", // 파비콘 허용 추가
                                              "/error"        // 에러 페이지 허용 추가
                                      )
                                      .permitAll()
                                      .requestMatchers(HttpMethod.POST, "/api/v2/user").permitAll()
                                      .requestMatchers(HttpMethod.GET, "/api/v2/user/{userId}").permitAll()
                                      .requestMatchers(HttpMethod.DELETE, "/api/v2/user/{userId}").hasRole("ADMIN")
                                      .anyRequest().authenticated())
              .oauth2Login(
                      oauth2 ->
                              oauth2
                                      .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                                      .successHandler(oAuth2SuccessHandler))
              .exceptionHandling(
                      exceptionHandling ->
                              exceptionHandling.authenticationEntryPoint(jwtAuthenticationEntryPoint))
              .sessionManagement(
                      sessionManagement ->
                              sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

      httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
      return httpSecurity.build();
  }

    // [핵심 추가] 프론트엔드와 쿠키를 주고받기 위한 CORS 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 1. 프론트엔드 주소 허용 (와일드카드 '*' 사용 불가)
        configuration.setAllowedOrigins(java.util.List.of("http://localhost:3000", "http://127.0.0.1:5500", "http://localhost:5500"));

        // 2. 허용할 HTTP 메서드
        configuration.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // 3. 허용할 헤더
        configuration.setAllowedHeaders(java.util.List.of("*"));

        // 4. [매우 중요] 쿠키 전송 허용
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}