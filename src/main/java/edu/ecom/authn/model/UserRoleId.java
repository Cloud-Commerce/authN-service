package edu.ecom.authn.model;

import java.io.Serializable;
import lombok.Data;

@Data
public class UserRoleId implements Serializable {
  private Long user;  // matches name of UserRole.user field
  private Role role;  // matches name of UserRole.role field

}