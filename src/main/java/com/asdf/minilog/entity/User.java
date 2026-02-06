package com.asdf.minilog.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class User {

  private static PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true)
  private String username;

  @Column(nullable = false)
  private String password;

  @CreatedDate
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @LastModifiedDate
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
  @Enumerated(EnumType.STRING)
  @Column(name = "role")
  private Set<Role> roles;

  @OneToMany(
      mappedBy = "author",
      cascade = CascadeType.ALL,
      orphanRemoval = true,
      fetch = FetchType.LAZY)
  private List<Article> articles;

  public static UserBuilder builder() {
    return new UserBuilder();
  }

  public void setPassword(String password) {
    this.password = passwordEncoder.encode(password);
  }

  public static class UserBuilder {
    private Long id;
    private String username;
    private String password;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Set<Role> roles;
    private List<Article> articles;
    private static PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public UserBuilder id(Long id) {
      this.id = id;
      return this;
    }

    public UserBuilder username(String username) {
      this.username = username;
      return this;
    }

    public UserBuilder password(String password) {
      this.password = passwordEncoder.encode(password);
      return this;
    }

    public UserBuilder createdAt(LocalDateTime createdAt) {
      this.createdAt = createdAt;
      return this;
    }

    public UserBuilder updatedAt(LocalDateTime updatedAt) {
      this.updatedAt = updatedAt;
      return this;
    }

    public UserBuilder roles(Set<Role> roles) {
      this.roles = roles;
      return this;
    }

    public UserBuilder articles(List<Article> articles) {
      this.articles = articles;
      return this;
    }

    public User build() {
      User user = new User();
      user.id = this.id;
      user.username = this.username;
      user.password = this.password;
      user.createdAt = this.createdAt;
      user.updatedAt = this.updatedAt;
      user.roles = this.roles;
      user.articles = this.articles;
      return user;
    }
  }
}
