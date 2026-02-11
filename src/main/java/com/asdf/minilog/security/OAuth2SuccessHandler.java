package com.asdf.minilog.security;

import com.asdf.minilog.entity.Role;
import com.asdf.minilog.entity.User;
import com.asdf.minilog.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
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

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {
    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
    Map<String, Object> attributes = oAuth2User.getAttributes();

    // 1. 구글 정보 추출
    String email = (String) attributes.get("email");
    String username = email; // 또는 username으로 활용 가능

      System.out.println("구글에서 받아온 이메일: " + attributes);

    // 2. DB 확인 및 가입/업데이트 로직
    User user =
        userRepository
            .findByUsername(username)
            .orElseGet(
                () -> {
                  // 신규 유저 생성 (UserBuilder 활용)
                  User newUser =
                      User.builder()
                          .username(email) // email을 username으로 사용
                          .password(UUID.randomUUID().toString()) // 소셜로그인은 비번이 필요없으므로 난수 생성
                          .email(email)
                          .roles(Collections.singleton(Role.ROLE_AUTHOR)) // Role 엔티티/이넘에 맞게 수정 필요
                          .build();
                  return userRepository.save(newUser);
                });

    // 3. 토큰 생성을 위한 UserDetails 로드
    // UserDetails의 username으로 email(username)을 사용합니다.
    UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());

    // 4. JwtUtil을 사용하여 토큰 발행 (전달해주신 메서드 형식: userDetails, userId)
    String token = jwtUtil.generateToken(userDetails, user.getId());

    // 5. 쿠키 생성 및 설정
      Cookie authCookie = new Cookie("Authorization", token);
      authCookie.setHttpOnly(true);   // JS에서 접근 불가 (보안 핵심)
      authCookie.setSecure(false);    // 개발 단계(http)에서는 false, 배포(https) 시 true
      authCookie.setPath("/");        // 모든 경로에서 쿠키 전송
      authCookie.setMaxAge(60 * 60 * 24); // 1일 유지

      // 응답에 쿠키 추가
      response.addCookie(authCookie);

    // 6. 프론트엔드로 리다이렉트
      String targetUrl = "http://localhost:5500/feed.html?userId=" + user.getId();
      getRedirectStrategy().sendRedirect(request, response, targetUrl);
  }
}
