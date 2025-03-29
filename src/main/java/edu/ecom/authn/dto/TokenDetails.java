package edu.ecom.authn.dto;

import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenDetails {
  String username;
  String id;
  String token;
  Date issuedAt;
  Date expiration;
  String state;
  String remarks;
}
