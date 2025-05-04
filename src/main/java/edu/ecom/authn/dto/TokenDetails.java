package edu.ecom.authn.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.jsonwebtoken.Claims;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
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

  @JsonIgnore //Not to cache or directly sent in body to gateway
  String token;

  Date issuedAt;

  Date expiration;

  @JsonIgnore //Not to be sent to gateway directly
  Claims claims;

  Map<String, String> clientMetadata;

  Collection<String> roles;

  String state;
  String remarks;
  boolean genuine;
  boolean expired;
}
