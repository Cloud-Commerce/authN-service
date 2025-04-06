package edu.ecom.authn.dto;

import java.util.Collection;
import java.util.List;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Builder
@Data
public class UserDetailsDto {

  private Long id;
  private String username;
  private String password;
  private List<String> roles;
  private Collection<? extends GrantedAuthority> authorities;

  public Collection<? extends GrantedAuthority> getAuthorities() {
    if(this.authorities == null) {
      this.authorities = roles.stream()
          .map(SimpleGrantedAuthority::new)
          .toList();
    }
    return this.authorities;
  }

}
