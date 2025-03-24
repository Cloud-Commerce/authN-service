package edu.ecom.authn.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class JwtResponse {
  // Getters and Setters
  private String token;
  private static String type = "Bearer";

}