package com.asdf.minilog.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.asdf.minilog.dto.ArticleResponseDto;
import com.asdf.minilog.entity.Article;
import com.asdf.minilog.entity.Follow;
import com.asdf.minilog.entity.User;
import com.asdf.minilog.repository.ArticleRepository;
import com.asdf.minilog.repository.FollowRepository;
import com.asdf.minilog.repository.UserRepository;
import java.time.format.DateTimeFormatter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
@ExtendWith(SpringExtension.class)
public class ArticleServiceTest {
  @Container
  public static MySQLContainer<?> mysqlContainer =
      new MySQLContainer<>("mysql:8.0.32")
          .withDatabaseName("testdb")
          .withUsername("test")
          .withPassword("test");

  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", mysqlContainer::getJdbcUrl);
    registry.add("spring.datasource.username", mysqlContainer::getUsername);
    registry.add("spring.datasource.password", mysqlContainer::getPassword);
  }

  private ArticleService articleService;

  @Autowired private ArticleRepository articleRepository;

  @Autowired private UserRepository userRepository;

  @Autowired private FollowRepository followRepository;

  User user1;
  User user2;
  Article article1;
  Article article2;
  Follow follow1;

  DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

  @BeforeEach
  @Transactional
  void setUp() {
    followRepository.deleteAll();
    articleRepository.deleteAll();
    userRepository.deleteAll();

    articleService = new ArticleService(articleRepository, userRepository);

    user1 = userRepository.save(User.builder().username("user1").password("user1").build());
    user2 = userRepository.save(User.builder().username("user2").password("user2").build());

    article1 =
        articleRepository.save(
            Article.builder()
                .content("test article1")
                .author(userRepository.findById(user1.getId()).get())
                .build());
    article2 =
        articleRepository.save(
            Article.builder()
                .content("test article2")
                .author(userRepository.findById(user2.getId()).get())
                .build());

    follow1 = Follow.builder().follower(user2).followee(user1).build();
    followRepository.save(follow1);
  }

  @Test
  @Transactional
  void testCreateArticle() {
    ArticleResponseDto article = articleService.createArticle("test3", user1.getId());

    assertThat(article.getContent()).isEqualTo("test3");
    assertThat(article.getAuthorId()).isEqualTo(user1.getId());
    assertThat(articleRepository.findAll().size()).isEqualTo(3);
  }

  @Test
  @Transactional
  void testGetArticleById() {
    ArticleResponseDto article = articleService.getArticleById(article1.getId());

    assertThat(article.getArticleId()).isEqualTo(article1.getId());
    assertThat(article.getContent()).isEqualTo(article1.getContent());
    assertThat(article.getAuthorId()).isEqualTo(article1.getAuthor().getId());
    assertThat(article.getAuthorName()).isEqualTo(article1.getAuthor().getUsername());
    assertThat(dateTimeFormatter.format(article.getCreatedAt()))
        .isEqualTo(dateTimeFormatter.format(article1.getCreatedAt()));
  }

  @Test
  @Transactional
  void testGetArticleListByUserId() {
    ArticleResponseDto article = articleService.getArticleListByUserId(user1.getId()).getFirst();

    assertThat(article.getArticleId()).isEqualTo(article1.getId());
    assertThat(article.getContent()).isEqualTo(article1.getContent());
    assertThat(article.getAuthorId()).isEqualTo(article1.getId());
    assertThat(article.getAuthorName()).isEqualTo(article1.getAuthor().getUsername());
    assertThat(dateTimeFormatter.format(article.getCreatedAt()))
        .isEqualTo(dateTimeFormatter.format(article1.getCreatedAt()));
  }

  @Test
  @Transactional
  void testGetFeedListByFollowerId() {
    ArticleResponseDto article =
        articleService.getFeedListByFollowerId(follow1.getFollower().getId()).getFirst();
    var target = articleService.getArticleListByUserId(article.getAuthorId()).getFirst();

    assertThat(article.getArticleId()).isEqualTo(target.getArticleId());
    assertThat(article.getContent()).isEqualTo(target.getContent());
    assertThat(article.getAuthorId()).isEqualTo(target.getAuthorId());
    assertThat(article.getAuthorName()).isEqualTo(target.getAuthorName());
    assertThat(dateTimeFormatter.format(article.getCreatedAt()))
        .isEqualTo(dateTimeFormatter.format(target.getCreatedAt()));
  }

  @Test
  @Transactional
  void testDeleteArticle() {
    assertThat(articleRepository.findAll().size()).isEqualTo(2);
    Long userId = article1.getAuthor().getId(); // TODO: Change to use Token to get userId
    articleService.deleteArticle(userId, article1.getId());

    assertThat(articleRepository.findAll().size()).isEqualTo(1);
  }

  @Test
  @Transactional
  void testUpdateArticle() {
    Long userId = article1.getAuthor().getId(); // TODO: Change to use Token to get userId
    ArticleResponseDto article =
        articleService.updateArticle(userId, article1.getId(), "updated article 1");

    assertThat(article.getArticleId()).isEqualTo(article1.getId());
    assertThat(article.getContent()).isEqualTo("updated article 1");
    assertThat(article.getAuthorId()).isEqualTo(article1.getAuthor().getId());
    assertThat(article.getAuthorName()).isEqualTo(article1.getAuthor().getUsername());
    assertThat(dateTimeFormatter.format(article.getCreatedAt()))
        .isEqualTo(dateTimeFormatter.format(article1.getCreatedAt()));
  }
}
