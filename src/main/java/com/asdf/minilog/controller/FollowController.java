package com.asdf.minilog.controller;

import com.asdf.minilog.dto.FollowRequestDto;
import com.asdf.minilog.dto.FollowResponseDto;
import com.asdf.minilog.security.MinilogUserDetails;
import com.asdf.minilog.service.FollowService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/v2/follow")
public class FollowController {

  private final FollowService followService;

  @Autowired
  public FollowController(FollowService followService) {
    this.followService = followService;
  }

  @PostMapping
  @Operation(summary = "팔로우")
  @ApiResponses({
    @ApiResponse(responseCode = "200", description = "성공"),
    @ApiResponse(responseCode = "404", description = "사용자 없음")
  })
  public ResponseEntity<FollowResponseDto> follow(
      @AuthenticationPrincipal MinilogUserDetails userDetails,
      @RequestBody FollowRequestDto request) {
    Long followerId = userDetails.getId();
    Long followeeId = request.getFolloweeId();

    FollowResponseDto follow = followService.follow(followerId, followeeId);
    return ResponseEntity.ok(follow);
  }

  @DeleteMapping
  @Operation(summary = "언팔로우")
  @ApiResponses({
    @ApiResponse(responseCode = "200", description = "성공"),
    @ApiResponse(responseCode = "404", description = "사용자 없음")
  })
  public ResponseEntity<Void> unfollow(
      @AuthenticationPrincipal MinilogUserDetails userDetails, @RequestParam Long followeeId) {
    followService.unfollow(userDetails.getId(), followeeId);
    return ResponseEntity.ok().build();
  }

  @GetMapping("/{followerId}")
  @Operation(summary = "팔로잉 목록 조회")
  @ApiResponses({
    @ApiResponse(responseCode = "200", description = "성공"),
    @ApiResponse(responseCode = "404", description = "사용자 없음")
  })
  public ResponseEntity<List<FollowResponseDto>> getFollowList(@PathVariable Long followerId) {
    List<FollowResponseDto> follows = followService.getFollowList(followerId);
    return ResponseEntity.ok(follows);
  }
}
