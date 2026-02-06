package com.asdf.minilog.security;

import com.asdf.minilog.entity.Role;
import org.springframework.security.core.GrantedAuthority;

public class MinilogGrantedAuthority implements GrantedAuthority {

  private final Role role;

  public MinilogGrantedAuthority(Role role) {
    this.role = role;
  }

  @Override
  public String getAuthority() {
    return role.name();
  }

  @Override
  public boolean equals(Object o) {
    // 동일한 객체인 경우
    if (this == o) {
      return true;
    }
    // 다른 객체이지만 role이 같은 경우
    if (o instanceof MinilogGrantedAuthority) {
      return role.equals(((MinilogGrantedAuthority) o).role);
    }
    return false;
  }

  @Override
  // Hash 기반 컬렉션(Set, Map)에 넣을 때 같은 role인 경우를 판별
  public int hashCode() {
    return role.hashCode();
  }

  @Override
  // 디버깅이나 로그 출력 시 문자열로 보이도록 함
  public String toString() {
    return role.name();
  }
}
