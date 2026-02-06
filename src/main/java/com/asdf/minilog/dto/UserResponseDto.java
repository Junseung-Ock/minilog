package com.asdf.minilog.dto;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;

@Data
@Builder
public class UserResponseDto {
  @NonNull private Long id;
  @NonNull private String username;
}
