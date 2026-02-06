package com.asdf.minilog.entity;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class UserTest {

  PasswordEncoder passwordEncoder;

  @BeforeEach
  void setUp() {
    passwordEncoder = new BCryptPasswordEncoder();
  }

  @Test
  void testUserCreation() {
    User user =
        User.builder()
            .username("testuser")
            .password("password")
            .createdAt(LocalDateTime.now())
            .updatedAt(LocalDateTime.now())
            .articles(Collections.emptyList())
            .build();

    assertThat(user.getUsername()).isEqualTo("testuser");
    System.out.println("User: " + user.getPassword());
    assertThat(passwordEncoder.matches("password", user.getPassword())).isTrue();
    assertThat(user.getArticles()).isEmpty();
  }

  @Test
  void testSetPassword() {
    String rawPassword = "newpassword";

    User user = User.builder().username("testuser").build();
    user.setPassword(rawPassword);

    assertThat(passwordEncoder.matches(rawPassword, user.getPassword())).isTrue();
  }

  @Test
  void testUserArticles() {
    User user =
        User.builder()
            .username("testuser")
            .password("password")
            .createdAt(LocalDateTime.now())
            .updatedAt(LocalDateTime.now())
            .articles(Collections.emptyList())
            .build();

    Article article = Article.builder().content("test article").author(user).build();

    user.setArticles(Collections.singletonList(article));

    assertThat(user.getArticles()).hasSize(1);
    assertThat(user.getArticles().get(0).getContent()).isEqualTo("test article");
  }
}
