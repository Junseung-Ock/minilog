package com.asdf.minilog.service;

import com.asdf.minilog.dto.ArticleResponseDto;
import com.asdf.minilog.entity.Article;
import com.asdf.minilog.entity.User;
import com.asdf.minilog.exception.ArticleNotFoundException;
import com.asdf.minilog.exception.NotAuthorizedException;
import com.asdf.minilog.exception.UserNotFoundException;
import com.asdf.minilog.repository.ArticleRepository;
import com.asdf.minilog.repository.UserRepository;
import com.asdf.minilog.util.EntityDtoMapper;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(isolation = Isolation.REPEATABLE_READ)
public class ArticleService {

  private final ArticleRepository articleRepository;
  private final UserRepository userRepository;

  @Autowired
  public ArticleService(ArticleRepository articleRepository, UserRepository userRepository) {
    this.articleRepository = articleRepository;
    this.userRepository = userRepository;
  }

  public ArticleResponseDto createArticle(String content, Long userId) {
    User user =
        userRepository
            .findById(userId)
            .orElseThrow(
                () ->
                    new UserNotFoundException(
                        String.format("해당 아이디(%d)를 가진 사용자를 찾을 수 없습니다", userId)));

    Article article = Article.builder().content(content).author(user).build();

    Article savedArticle = articleRepository.save(article);
    return EntityDtoMapper.toDto(savedArticle);
  }

  public void deleteArticle(Long authorId, Long articleId) {
    Article article =
        articleRepository
            .findById(articleId)
            .orElseThrow(
                () ->
                    new ArticleNotFoundException(
                        String.format("해당 아이디(%d)를 가진 게시글을 찾을 수 없습니다.", articleId)));
    if (!article.getAuthor().getId().equals(authorId)) {
      throw new NotAuthorizedException("게시글 작성자만 삭제할 수 있습니다");
    }
    articleRepository.deleteById(articleId);
  }

  public ArticleResponseDto updateArticle(Long authorId, Long articleId, String content) {
    Article article =
        articleRepository
            .findById(articleId)
            .orElseThrow(
                () ->
                    new ArticleNotFoundException(
                        String.format("해당 아이디(%d)를 가진 게시글을 찾을 수 없습니다.", articleId)));

    if (!article.getAuthor().getId().equals(authorId)) {
      throw new NotAuthorizedException("게시글 작성자만 수정할 수 있습니다");
    }
    article.setContent(content);
    Article updatedArticle = articleRepository.save(article);

    return EntityDtoMapper.toDto(updatedArticle);
  }

  @Transactional(readOnly = true)
  public ArticleResponseDto getArticleById(Long articleId) {
    Article article =
        articleRepository
            .findById(articleId)
            .orElseThrow(
                () ->
                    new ArticleNotFoundException(
                        String.format("해당 아이디(%d)를 가진 게시글을 찾을 수 없습니다.", articleId)));

    return EntityDtoMapper.toDto(article);
  }

  @Transactional(readOnly = true)
  public List<ArticleResponseDto> getFeedListByFollowerId(Long userId) {
    User user =
        userRepository
            .findById(userId)
            .orElseThrow(
                () ->
                    new UserNotFoundException(
                        String.format("해당 아이디(%d)를 가진 사용자를 찾을 수 없습니다.", userId)));

    var feedList = articleRepository.findAllByFollowerId(user.getId());
    return feedList.stream().map(EntityDtoMapper::toDto).toList();
  }

  @Transactional(readOnly = true)
  public List<ArticleResponseDto> getArticleListByUserId(Long userId) {
    User user =
        userRepository
            .findById(userId)
            .orElseThrow(
                () ->
                    new UserNotFoundException(
                        String.format("해당 아이디(%d)를 가진 사용자를 찾을 수 없습니다.", userId)));

    var articleList = articleRepository.findAllByAuthorId(user.getId());
    return articleList.stream().map(EntityDtoMapper::toDto).toList();
  }
}
