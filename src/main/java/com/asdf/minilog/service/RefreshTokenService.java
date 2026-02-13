package com.asdf.minilog.service;

import com.asdf.minilog.entity.RefreshToken;
import com.asdf.minilog.repository.RefreshTokenRepository;
import com.asdf.minilog.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    // 1. 리프레시 토큰 생성 또는 업데이트
    @Transactional
    public String createOrUpdateRefreshToken(Long userId, String tokenString) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userRepository.findById(userId).get());
        refreshToken.setToken(tokenString);
        // JwtUtil에 정의된 REFRESH_TOKEN_VALIDITY(7일)와 맞춤
        refreshToken.setExpiryDate(Instant.now().plusSeconds(7 * 24 * 60 * 60));

        // 기존에 해당 유저의 토큰이 있다면 삭제 후 새로 저장 (1인 1기기 세션 유지 시)
        refreshTokenRepository.deleteByUser(refreshToken.getUser());

        refreshTokenRepository.save(refreshToken);
        return tokenString;
    }

    // 2. 토큰 만료 여부 확인
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    // 3. 토큰 문자열로 RefreshToken 엔티티 조회
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    // 4. 로그아웃 시 토큰 삭제
    @Transactional
    public void deleteByUserId(Long userId) {
        userRepository.findById(userId).ifPresent(refreshTokenRepository::deleteByUser);
    }
}