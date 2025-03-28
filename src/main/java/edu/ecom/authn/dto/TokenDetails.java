package edu.ecom.authn.dto;

import java.util.Date;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenDetails {
  String username;
  String id;
  String token;
  Date issuedAt;
  Date expiration;
  String state;
  String remarks;
}
