package com.asdf.minilog.security;

import java.util.Collection;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MinilogUserDetails implements UserDetails {
  private Long id;
  private String username;
  private String password;
  private Collection<? extends GrantedAuthority> authorities;
}
