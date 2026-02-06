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

  @Query(
      "SELECT  a FROM Article a JOIN a.author u JOIN Follow f"
          + " ON u.id = f.followee.id WHERE" // followee가 작성한 글 중에
          + " f.follower.id = :authorId ORDER BY a.createdAt DESC") // 특정 유저가 팔로우하는 글을 반환
  List<Article> findAllByFollowerId(@Param("authorId") Long authorId);
}
