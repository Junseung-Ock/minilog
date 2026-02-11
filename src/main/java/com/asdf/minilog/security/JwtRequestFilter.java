package com.asdf.minilog.security;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
  private static final Logger logger = LoggerFactory.getLogger(JwtRequestFilter.class);

  @Autowired @Lazy
  private UserDetailsService jwtUserDetailsService;

  @Autowired private JwtUtil jwtTokenUtil;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String requestTokenHeader = request.getHeader("Authorization");
    String username = null;
    String jwt = null;

      // 1단계: 쿠키에서 JWT 추출 시도
      Cookie[] cookies = request.getCookies();
      if (cookies != null) {
          for (Cookie cookie : cookies) {
              if ("Authorization".equals(cookie.getName())) {
                  jwt = cookie.getValue();
                  break;
              }
          }
      }

      // 2단계: 쿠키에 토큰이 없다면 기존처럼 헤더에서 추출 시도
      if (jwt == null && requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
          jwt = requestTokenHeader.substring(7);
      }

      // 3단계: 추출된 토큰이 있다면 username 확인
      if (jwt != null) {
          try {
              username = jwtTokenUtil.getUsernameFromToken(jwt);
          } catch (IllegalArgumentException e) {
              logger.error("Unable to get JWT", e);
          } catch (ExpiredJwtException e) {
              logger.warn("JWT has expired", e);
          } catch (Exception e) {
              logger.error("JWT validation error", e);
          }
      } else {
          // 로그인하지 않은 사용자가 접근할 때 발생하는 로그 (필요없으면 주석 처리 가능)
          logger.debug("JWT Token is missing");
      }

    // 토큰에서 username을 정상적으로 추출했고, 아직 현재 요청에 대해 인증(Authentication)이 설정되지 않은 경우에만 진행
    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);

      if (jwtTokenUtil.validateToken(jwt, userDetails)) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
            new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
      } else {
        logger.warn("JWT is not valid");
      }
    }
    // 현재 필터가 자신의 로직을 수행한 뒤, 다음 필터로 제어를 넘기는 것
    filterChain.doFilter(request, response);
  }
}
