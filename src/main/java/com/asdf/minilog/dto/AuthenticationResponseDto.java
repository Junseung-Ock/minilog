package com.asdf.minilog.dto;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;

@Data
@Builder
public class AuthenticationResponseDto {
  @NonNull private String jwt;
}
