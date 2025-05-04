package edu.ecom.authn.service;

import edu.ecom.authn.dto.AuthDetails;
import edu.ecom.authn.dto.TokenDetails;
import edu.ecom.authn.dto.UserDetailsDto;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Optional;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthHelper {

  private final JwtServiceProvider jwtServiceProvider;
  private final TokenSessionManagementService tokenSessionManagementService;
  private final RequestMetadata requestMetadata;

  public JwtAuthHelper(JwtServiceProvider jwtServiceProvider,
      TokenSessionManagementService tokenSessionManagementService, RequestMetadata requestMetadata) {
    this.jwtServiceProvider = jwtServiceProvider;
    this.tokenSessionManagementService = tokenSessionManagementService;
    this.requestMetadata = requestMetadata;
  }

  public TokenDetails getVerifiedDetails() {
    TokenDetails tokenDetails = Optional.ofNullable(extractToken(requestMetadata.getRequest()))
        .map(jwtServiceProvider::parseToken).orElseThrow(() -> new SessionAuthenticationException("Missing Token"));

    if (!tokenDetails.isGenuine()) {
      throw new SessionAuthenticationException("Invalid Token");
    }

    Claims claims = tokenDetails.getClaims();

    if(!tokenSessionManagementService.isSessionActive(tokenDetails.getUsername(), tokenDetails.getId()))
      throw new SessionAuthenticationException("Expired Session : User Logged out!");

    if(tokenDetails.isExpired()) {
      if(!requestMetadata.generateClientFingerprint().equals(claims.get("fp"))) {
        throw new SessionAuthenticationException("Token stolen");
      }
    }
    return tokenDetails;
  }

  public Authentication createAuthentication(TokenDetails tokenDetails) {
    String username = tokenDetails.getUsername();
    Collection<? extends GrantedAuthority> authorities = jwtServiceProvider.extractAuthorities(
        tokenDetails.getClaims());

    UserDetailsDto userDetails = UserDetailsDto.builder()
        .username(username).password(tokenDetails.getId()).authorities(authorities).build(); // user password is not needed here

    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
        userDetails, null, userDetails.getAuthorities()); // synced with UsernamePasswordAuthenticationFilter strategy
    WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetailsSource().buildDetails(requestMetadata.getRequest());

    authentication.setDetails(AuthDetails.builder().webAuthenticationDetails(
        webAuthenticationDetails).claims(tokenDetails.getClaims()).build());

    return authentication;
  }

  private String extractToken(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
      return bearerToken.split(" ")[1];
    }
    return null;
  }

  public Authentication createAuthentication(UserDetailsDto userDetails) {
    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,
        null, userDetails.getAuthorities());
    WebAuthenticationDetails webAuthenticationDetails = (new WebAuthenticationDetailsSource()).buildDetails(this.requestMetadata.getRequest());
    authentication.setDetails(AuthDetails.builder().webAuthenticationDetails(webAuthenticationDetails).build());
    return authentication;
  }
}
