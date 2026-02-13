package com.asdf.minilog.security;

import com.asdf.minilog.entity.Role;
import com.asdf.minilog.entity.User;
import com.asdf.minilog.repository.UserRepository;
import com.asdf.minilog.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService; // [추가]

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = (String) oAuth2User.getAttributes().get("email");

        User user = userRepository.findByUsername(email)
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .username(email)
                            .password(UUID.randomUUID().toString())
                            .email(email)
                            .roles(Collections.singleton(Role.ROLE_AUTHOR))
                            .build();
                    return userRepository.save(newUser);
                });

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());

        // 1. Access Token 생성 및 쿠키 설정 (30분)
        String accessToken = jwtUtil.generateAccessToken(userDetails, user.getId());
        Cookie authCookie = new Cookie("Authorization", accessToken);
        authCookie.setHttpOnly(true);
        authCookie.setPath("/"); // 모든 요청에 쿠키를 함께 전송
        authCookie.setMaxAge(30 * 60); // 30분
        response.addCookie(authCookie);

        // 2. Refresh Token 생성, DB 저장 및 쿠키 설정 (7일)
        String refreshTokenString = jwtUtil.generateRefreshToken(userDetails);
        refreshTokenService.createOrUpdateRefreshToken(user.getId(), refreshTokenString); // [실제 연결]

        Cookie refreshCookie = new Cookie("RefreshToken", refreshTokenString);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/api/v2/auth/refresh"); // 재발급 경로에서만 전송
        refreshCookie.setMaxAge(7 * 24 * 60 * 60); // 7일
        response.addCookie(refreshCookie);

        // 3. 리다이렉트
        String targetUrl = "http://localhost:5500/feed.html?userId=" + user.getId();
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}