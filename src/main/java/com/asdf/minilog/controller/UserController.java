package com.asdf.minilog.controller;

import com.asdf.minilog.dto.UserRequestDto;
import com.asdf.minilog.dto.UserResponseDto;
import com.asdf.minilog.security.MinilogUserDetails;
import com.asdf.minilog.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/v2/user")
public class UserController {

  private final UserService userService;

  @Autowired
  public UserController(UserService userService) {
    this.userService = userService;
  }

  @GetMapping
  @Operation(summary = "사용자 목록 조회")
  @ApiResponses(@ApiResponse(responseCode = "200", description = "성공"))
  public ResponseEntity<Iterable<UserResponseDto>> getUsers() {
    return ResponseEntity.ok(userService.getUsers());
  }

  @GetMapping("/{userId}")
  @Operation(summary = "사용자 조회")
  @ApiResponses({
    @ApiResponse(responseCode = "200", description = "성공"),
    @ApiResponse(responseCode = "404", description = "사용자 없음")
  })
  public ResponseEntity<UserResponseDto> getUser(@PathVariable Long userId) {
    Optional<UserResponseDto> user = userService.getUserById(userId);
    return user.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
  }

  @PostMapping
  @Operation(summary = "사용자 생성")
  @ApiResponses({@ApiResponse(responseCode = "200", description = "성공")})
  public ResponseEntity<UserResponseDto> createUser(@RequestBody UserRequestDto user) {
    UserResponseDto createdUser = userService.createUser(user);
    return ResponseEntity.ok(createdUser);
  }

  @PutMapping("/{userId}")
  @Operation(summary = "사용자 수정")
  @ApiResponses({
    @ApiResponse(responseCode = "200", description = "성공"),
    @ApiResponse(responseCode = "404", description = "사용자 없음")
  })
  public ResponseEntity<UserResponseDto> updateUser(
      @PathVariable Long userId,
      @RequestBody UserRequestDto updatedUser,
      @AuthenticationPrincipal MinilogUserDetails userDetails) {
    UserResponseDto user = userService.updateUser(userDetails, userId, updatedUser);
    return ResponseEntity.ok(user);
  }

  @DeleteMapping("/{userId}")
  @PreAuthorize("hasRole('ADMIN')")
  @Operation(summary = "사용자 삭제")
  @ApiResponses({
    @ApiResponse(responseCode = "204", description = "성공"),
    @ApiResponse(responseCode = "404", description = "사용자 없음")
  })
  public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
    userService.deleteUser(userId);
    return ResponseEntity.noContent().build();
  }
}
