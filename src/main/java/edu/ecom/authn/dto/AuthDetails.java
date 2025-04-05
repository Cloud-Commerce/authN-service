package edu.ecom.authn.dto;

import io.jsonwebtoken.Claims;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Data
@Builder
public class AuthDetails {
  WebAuthenticationDetails webAuthenticationDetails;
  Claims claims;
}
