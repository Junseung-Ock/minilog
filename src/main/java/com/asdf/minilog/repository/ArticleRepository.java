package com.asdf.minilog.repository;

import com.asdf.minilog.entity.Article;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ArticleRepository extends JpaRepository<Article, Long> {
  List<Article> findAllByAuthorId(Long authorId);

    @Query("SELECT a FROM Article a " +
            "WHERE a.author.id = :authorId " + // 1. 내가 쓴 글이거나
            "OR a.author.id IN (" +            // 2. 작성자가 다음 리스트에 포함된 경우
            "  SELECT f.followee.id FROM Follow f WHERE f.follower.id = :authorId" + // 내가 팔로우하는 사람들
            ") " +
            "ORDER BY a.createdAt DESC")
    List<Article> findAllByFollowerId(@Param("authorId") Long authorId);
}
