package edu.ecom.authn.model;

import java.io.Serializable;
import java.util.Objects;
import lombok.Data;

@Data
public class UserRoleId implements Serializable {
  private Long user;  // matches name of UserRole.user field
  private Role role;  // matches name of UserRole.role field

  @Override
  public int hashCode() {
    return Objects.hash(user, role);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof UserRoleId that)) return false;
    return Objects.equals(user, that.user) &&
        role == that.role;
  }
}