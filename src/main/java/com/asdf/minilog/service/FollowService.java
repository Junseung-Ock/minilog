package com.asdf.minilog.service;

import com.asdf.minilog.dto.FollowResponseDto;
import com.asdf.minilog.entity.Follow;
import com.asdf.minilog.entity.User;
import com.asdf.minilog.exception.UserNotFoundException;
import com.asdf.minilog.repository.FollowRepository;
import com.asdf.minilog.repository.UserRepository;
import com.asdf.minilog.util.EntityDtoMapper;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class FollowService {

  private final UserRepository userRepository;
  private final FollowRepository followRepository;

  @Autowired
  public FollowService(UserRepository userRepository, FollowRepository followRepository) {
    this.userRepository = userRepository;
    this.followRepository = followRepository;
  }

  public FollowResponseDto follow(Long followerId, Long followeeId) {
    if (followerId.equals(followeeId)) {
      throw new IllegalArgumentException("자신을 팔로우할 수 없습니다.");
    }

    User follower =
        userRepository
            .findById(followerId)
            .orElseThrow(
                () ->
                    new UserNotFoundException(
                        String.format("팔로워 아이디(%d)를 가진 사용자를 찾을 수 없습니다.", followerId)));
    User followee =
        userRepository
            .findById(followeeId)
            .orElseThrow(
                () ->
                    new UserNotFoundException(
                        String.format("팔로잉 아이디(%d)를 가진 사용자를 찾을 수 없습니다.", followeeId)));

    Follow follow =
        followRepository.save(EntityDtoMapper.toEntity(follower.getId(), followee.getId()));
    return EntityDtoMapper.toDto(follow);
  }

  public void unfollow(Long followerId, Long followeeId) {
    Optional<Follow> follow =
        Optional.ofNullable(
            followRepository
                .findByFollowerIdAndFolloweeId(followerId, followeeId)
                .orElseThrow(
                    () ->
                        new UserNotFoundException(
                            String.format(
                                "팔로워(%d)와 팔로잉(%d)을 연결하는 Follow를 찾을 수 없습니다.",
                                followerId, followeeId))));
    followRepository.delete(follow.get()); // follow는 Optional 이므로 get을 통해 Follow로 변환
  }

  public List<FollowResponseDto> getFollowList(Long userId) {
    if (userRepository.findById(userId).isEmpty()) {
      throw new UserNotFoundException(String.format("해당 아이디(%d)를 가진 사용자를 찾을 수 없습니다.", userId));
    }

    return followRepository.findByFollowerId(userId).stream().map(EntityDtoMapper::toDto).toList();
  }
}
