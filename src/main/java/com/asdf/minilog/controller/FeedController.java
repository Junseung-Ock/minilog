package com.asdf.minilog.controller;

import com.asdf.minilog.dto.ArticleResponseDto;
import com.asdf.minilog.service.ArticleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/v2/feed")
public class FeedController {

  private final ArticleService articleService;

  @Autowired
  public FeedController(ArticleService articleService) {
    this.articleService = articleService;
  }

  @GetMapping
  @Operation(summary = "피드 조회")
  @ApiResponses({
    @ApiResponse(responseCode = "200", description = "성공"),
    @ApiResponse(responseCode = "404", description = "사용자 없음")
  })
  public ResponseEntity<List<ArticleResponseDto>> getFeed(@RequestParam Long followerId) {
    List<ArticleResponseDto> feedList = articleService.getFeedListByFollowerId(followerId);
    return ResponseEntity.ok(feedList);
  }
}
