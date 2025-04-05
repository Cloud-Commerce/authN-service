package edu.ecom.authn.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ChangePasswordRequest {

  private String username;

  @NotBlank(message = "Old Password cannot be blank")
  @Size(min = 6, max = 40, message = "Password must be between 6 and 40 characters")
  private String oldPassword;

  @NotBlank(message = "New Password cannot be blank")
  @Size(min = 6, max = 40, message = "Password must be between 6 and 40 characters")
  private String newPassword;

}