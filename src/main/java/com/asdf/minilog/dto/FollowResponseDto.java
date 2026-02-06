package com.asdf.minilog.dto;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;

@Data
@Builder
public class FollowResponseDto {
  @NonNull private Long followerId;
  @NonNull private Long followeeId;
}
