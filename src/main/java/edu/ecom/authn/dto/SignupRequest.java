package edu.ecom.authn.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SignupRequest {

  // Getters and Setters
  @NotBlank(message = "Username cannot be blank")
  @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
  private String username;

  @NotBlank(message = "Password cannot be blank")
  @Size(min = 6, max = 40, message = "Password must be between 6 and 40 characters")
  private String password;

}