package edu.ecom.authn.security;

import edu.ecom.authn.entity.User;
import edu.ecom.authn.model.Role;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Value
public class UserDetailsImpl implements UserDetails {

  Long id;
  String username;
  String password;
  Collection<? extends GrantedAuthority> authorities;

  public static UserDetails build(User user) {
    Set<SimpleGrantedAuthority> authorities = user.getRoles().stream().map(Role::name)
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toSet());

    return new UserDetailsImpl(
        user.getId(),
        user.getUsername(),
        user.getPassword(),
        authorities);
  }


  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}