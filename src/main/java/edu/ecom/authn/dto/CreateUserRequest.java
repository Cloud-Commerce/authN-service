package edu.ecom.authn.dto;

import edu.ecom.authn.model.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Data
@Builder
public class CreateUserRequest {

  @NotBlank(message = "Username cannot be blank")
  @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
  private String username;

  @NotBlank(message = "Password cannot be blank")
  @Size(min = 6, max = 40, message = "Password must be between 6 and 40 characters")
  private String password;

  private List<Role> roles;
}