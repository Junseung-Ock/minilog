package com.asdf.minilog.security;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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

  @Autowired private UserDetailsService jwtUserDetailsService;

  @Autowired private JwtUtil jwtTokenUtil;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String requestTokenHeader = request.getHeader("Authorization");
    String username = null;
    String jwt = null;

    // Authorization 헤더에서 JWT를 꺼내서 username을 확인하고, 문제가 있으면 로그를 남기는 부분
    if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
      jwt = requestTokenHeader.substring(7);
      try {
        username = jwtTokenUtil.getUsernameFromToken(jwt);
      } catch (IllegalArgumentException e) {
        logger.error("Unable to get JWT", e);
      } catch (ExpiredJwtException e) {
        logger.warn("JWT has expired", e);
      }
    } else {
      logger.warn("JWT does not begin with Bearer String");
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
