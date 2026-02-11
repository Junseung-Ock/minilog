package com.asdf.minilog.controller;

import com.asdf.minilog.dto.AuthenticationRequestDto;
import com.asdf.minilog.dto.AuthenticationResponseDto;
import com.asdf.minilog.dto.UserResponseDto;
import com.asdf.minilog.security.JwtUtil;
import com.asdf.minilog.service.UserService;
import jakarta.servlet.http.Cookie;
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

  @Autowired
  public AuthenticationController(
      AuthenticationManager authenticationManager,
      JwtUtil jwtTokenUtil,
      UserDetailsService userDetailsService,
      UserService userService) {
    this.authenticationManager = authenticationManager;
    this.jwtTokenUtil = jwtTokenUtil;
    this.userDetailsService = userDetailsService;
    this.userService = userService;
  }

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(
            @RequestBody AuthenticationRequestDto authRequest,
            HttpServletResponse response) { // HttpServletResponse 추가
        try {
            // 1. 비밀번호 검증 (실패 시 BadCredentialsException 발생)
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.getUsername(), authRequest.getPassword()));

            // 2. 유저 정보 로드
            UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
            UserResponseDto userResponseDto = userService.getUserByUsername(userDetails.getUsername());

            // 3. JWT 토큰 생성
            String jwt = jwtTokenUtil.generateToken(userDetails, userResponseDto.getId());

            // 4. 쿠키 생성 및 설정 (OAuth2SuccessHandler와 설정을 동일하게 맞춤)
            Cookie authCookie = new Cookie("Authorization", jwt);
            authCookie.setPath("/");
            authCookie.setHttpOnly(true); // JS 접근 방지
            authCookie.setMaxAge(60 * 60 * 24); // 1일 유지
            // authCookie.setSecure(true); // 배포 환경(HTTPS)에서 활성화

            // 5. 응답에 쿠키 추가
            response.addCookie(authCookie);

            // 6. 바디에는 토큰 대신 유저 정보를 반환 (프론트엔드 편의성)
            return ResponseEntity.ok(userResponseDto);

        } catch (BadCredentialsException e) {
            logger.error("Authentication failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
        } catch (Exception e) {
            logger.error("Internal error during login: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred during authentication.");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        // 1. 만료 시간이 0인 쿠키를 생성 (기존 쿠키와 이름, 경로가 같아야 함)
        Cookie cookie = new Cookie("Authorization", null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0); // 즉시 삭제 명령

        // 배포 환경이 HTTPS라면 추가 (로컬 개발 시엔 일단 주석 처리해도 됨)
        // cookie.setSecure(true);

        // 2. 응답 헤더에 쿠키 추가
        response.addCookie(cookie);

        return ResponseEntity.ok().body("Successfully logged out.");
    }
}
