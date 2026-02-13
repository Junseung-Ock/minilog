package com.asdf.minilog.controller;

import com.asdf.minilog.dto.AuthenticationRequestDto;
import com.asdf.minilog.dto.AuthenticationResponseDto;
import com.asdf.minilog.dto.UserResponseDto;
import com.asdf.minilog.entity.User;
import com.asdf.minilog.security.JwtUtil;
import com.asdf.minilog.service.RefreshTokenService;
import com.asdf.minilog.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v2/auth")
public class AuthenticationController {
  private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

  private AuthenticationManager authenticationManager;
  private JwtUtil jwtTokenUtil;
  private UserDetailsService userDetailsService;
  private UserService userService;
  private RefreshTokenService refreshTokenService;

  @Autowired
  public AuthenticationController(
      AuthenticationManager authenticationManager,
      JwtUtil jwtTokenUtil,
      UserDetailsService userDetailsService,
      UserService userService,
      RefreshTokenService refreshTokenService) {
    this.authenticationManager = authenticationManager;
    this.jwtTokenUtil = jwtTokenUtil;
    this.userDetailsService = userDetailsService;
    this.userService = userService;
    this.refreshTokenService = refreshTokenService;
  }

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(
            @RequestBody AuthenticationRequestDto authRequest,
            HttpServletResponse response) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

            UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
            UserResponseDto userResponseDto = userService.getUserByUsername(userDetails.getUsername());

            // 1. Access Token 생성 및 쿠키 설정 (30분)
            String accessToken = jwtTokenUtil.generateAccessToken(userDetails, userResponseDto.getId());
            Cookie authCookie = new Cookie("Authorization", accessToken);
            authCookie.setPath("/"); // 모든 요청에 쿠키를 함께 전송
            authCookie.setHttpOnly(true);
            authCookie.setMaxAge(30 * 60); // 30분
            response.addCookie(authCookie);

            // 2. Refresh Token 생성 및 DB 저장 (7일)
            String refreshTokenString = jwtTokenUtil.generateRefreshToken(userDetails);
            refreshTokenService.createOrUpdateRefreshToken(userResponseDto.getId(), refreshTokenString);

            // 3. Refresh Token 쿠키 설정
            Cookie refreshCookie = new Cookie("RefreshToken", refreshTokenString);
            refreshCookie.setPath("/api/v2/auth/refresh"); // 중요: 재발급 경로에서만 전송되도록 제한
            refreshCookie.setHttpOnly(true);
            refreshCookie.setMaxAge(7 * 24 * 60 * 60); // 7일
            response.addCookie(refreshCookie);

            return ResponseEntity.ok(userResponseDto);

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response, @RequestParam(required = false) Long userId) {
        // 1. DB에서 리프레시 토큰 삭제
        if (userId != null) {
            refreshTokenService.deleteByUserId(userId);
        }

        // 2. 쿠키 삭제 (Authorization & RefreshToken 둘 다)
        Cookie authCookie = new Cookie("Authorization", null);
        authCookie.setPath("/");
        authCookie.setMaxAge(0);
        response.addCookie(authCookie);

        Cookie refreshCookie = new Cookie("RefreshToken", null);
        refreshCookie.setPath("/api/v2/auth/refresh");
        refreshCookie.setMaxAge(0);
        response.addCookie(refreshCookie);

        return ResponseEntity.ok().body("Successfully logged out.");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        // 1. 쿠키에서 RefreshToken 추출
        Cookie[] cookies = request.getCookies();
        String refreshTokenString = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("RefreshToken")) {
                    refreshTokenString = cookie.getValue();
                    break;
                }
            }
        }

        if (refreshTokenString == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("리프레시 토큰이 없습니다. 다시 로그인하세요.");
        }

        // 2. DB 검증 및 새로운 액세스 토큰 생성
        try {
            return refreshTokenService.findByToken(refreshTokenString)
                    .map(refreshTokenService::verifyExpiration) // 만료 시간 체크 (DB상)
                    .map(refreshToken -> {
                        User user = refreshToken.getUser();
                        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());

                        // 새 액세스 토큰 생성
                        String newAccessToken = jwtTokenUtil.generateAccessToken(userDetails, user.getId());

                        // 3. 새 액세스 토큰을 쿠키에 저장
                        Cookie authCookie = new Cookie("Authorization", newAccessToken);
                        authCookie.setPath("/");
                        authCookie.setHttpOnly(true);
                        authCookie.setMaxAge(30 * 60); // 30분
                        // authCookie.setSecure(true); // 배포 시 활성화
                        response.addCookie(authCookie);

                        return ResponseEntity.ok("토큰 재발급 성공");
                    })
                    .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("유효하지 않은 리프레시 토큰입니다."));

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }
}
