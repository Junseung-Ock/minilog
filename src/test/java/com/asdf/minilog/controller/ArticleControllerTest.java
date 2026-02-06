package com.asdf.minilog.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.asdf.minilog.dto.ArticleRequestDto;
import com.asdf.minilog.dto.ArticleResponseDto;
import com.asdf.minilog.exception.ArticleNotFoundException;
import com.asdf.minilog.security.JwtUtil;
import com.asdf.minilog.security.MinilogUserDetails;
import com.asdf.minilog.service.ArticleService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

@ExtendWith(SpringExtension.class)
@WebMvcTest(ArticleController.class) // 웹 레이어만 테스트
@MockBean(JpaMetamodelMappingContext.class)
public class ArticleControllerTest {

  @Autowired private MockMvc mockMvc;

  @MockBean private ArticleService articleService;

  @MockBean private JwtUtil jwtUtil; // JwtUtil 의존성 주입

  private ObjectMapper objectMapper = new ObjectMapper();
  private LocalDateTime fixtureDateTime = LocalDateTime.of(2025, 1, 1, 0, 0, 0);
  private DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
  private String formattedFixtureDateTime = fixtureDateTime.format(formatter);

  @BeforeEach
  public void setup() {
    MockitoAnnotations.openMocks(this);

    MinilogUserDetails userDetails =
        new MinilogUserDetails(1L, "testuser", "password", List.of(() -> "ROLE_AUTHOR"));
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    SecurityContextHolder.getContext().setAuthentication(auth);
  }

  @Test
  public void testCreateArticle() throws Exception {
    ArticleRequestDto requestDto = ArticleRequestDto.builder().content("Test Content").build();
    ArticleResponseDto responseDto =
        ArticleResponseDto.builder()
            .articleId(1L)
            .content("Test Content")
            .authorId(1L)
            .authorName("testuser")
            .createdAt(fixtureDateTime)
            .build();
    when(articleService.createArticle(any(String.class), anyLong())).thenReturn(responseDto);

    mockMvc
        .perform(
            post("/api/v2/article")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto))
                .with(csrf()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.articleId").value(1L))
        .andExpect(jsonPath("$.content").value("Test Content"))
        .andExpect(jsonPath("$.authorId").value(1L))
        .andExpect(jsonPath("$.authorName").value("testuser"))
        .andExpect(jsonPath("$.createdAt").value(formattedFixtureDateTime));
  }

  @Test
  public void testGetArticle() throws Exception {
    ArticleResponseDto responseDto =
        ArticleResponseDto.builder()
            .articleId(1L)
            .content("Test Content")
            .authorId(1L)
            .authorName("testuser")
            .createdAt(fixtureDateTime)
            .build();
    when(articleService.getArticleById(anyLong())).thenReturn(responseDto);

    mockMvc
        .perform(get("/api/v2/article/1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.articleId").value(1L))
        .andExpect(jsonPath("$.content").value("Test Content"))
        .andExpect(jsonPath("$.authorId").value(1L))
        .andExpect(jsonPath("$.authorName").value("testuser"))
        .andExpect(jsonPath("$.createdAt").value(formattedFixtureDateTime));
  }

  @Test
  public void testUpdateArticle() throws Exception {
    Long userId = 1L;
    Long articleId = 1L;
    String updatedContent = "Updated Content";
    ArticleRequestDto requestDto = ArticleRequestDto.builder().content("Test Content").build();
    ArticleResponseDto responseDto =
        ArticleResponseDto.builder()
            .articleId(articleId)
            .content(updatedContent)
            .authorId(userId)
            .authorName("testuser")
            .createdAt(fixtureDateTime)
            .build();
    when(articleService.updateArticle(anyLong(), anyLong(), any(String.class)))
        .thenReturn(responseDto);

    mockMvc
        .perform(
            put("/api/v2/article/1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto))
                .with(csrf()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.articleId").value(articleId))
        .andExpect(jsonPath("$.content").value(updatedContent))
        .andExpect(jsonPath("$.authorId").value(userId))
        .andExpect(jsonPath("$.authorName").value("testuser"))
        .andExpect(jsonPath("$.createdAt").value(formattedFixtureDateTime));
  }

  @Test
  public void testDeleteArticle() throws Exception {
    mockMvc.perform(delete("/api/v2/article/1").with(csrf())).andExpect(status().isNoContent());
  }

  @Test
  public void testGetArticleByUserId() throws Exception {
    Long userId = 1L;
    Long articleId = 1L;
    ArticleResponseDto responseDto =
        ArticleResponseDto.builder()
            .articleId(articleId)
            .content("Test Content")
            .authorId(userId)
            .authorName("testuser")
            .createdAt(fixtureDateTime)
            .build();
    List<ArticleResponseDto> responseList = Collections.singletonList(responseDto);
    when(articleService.getArticleListByUserId(anyLong())).thenReturn(responseList);

    mockMvc
        .perform(get("/api/v2/article").param("authorId", "1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].articleId").value(articleId))
        .andExpect(jsonPath("$[0].content").value("Test Content"))
        .andExpect(jsonPath("$[0].authorId").value(userId))
        .andExpect(jsonPath("$[0].authorName").value("testuser"))
        .andExpect(jsonPath("$[0].createdAt").value(formattedFixtureDateTime));
  }

  @Test
  public void testGlobalExceptionHandler() throws Exception {
    when(articleService.getArticleById(anyLong()))
        .thenThrow(new ArticleNotFoundException("Article Not Found"));

    mockMvc
        .perform(get("/api/v2/article/999"))
        .andExpect(status().isNotFound())
        .andExpect(content().string("Article Not Found"));
  }
}
