package edu.ecom.authn.service;

import edu.ecom.authn.dto.TokenDetails;
import edu.ecom.authn.dto.TokenDetails.TokenDetailsBuilder;
import edu.ecom.authn.dto.UserDetailsDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtServiceProvider {

  private final RequestMetadata requestMetadata;
  private final SecretKey jwtSecretKey;
  private final long jwtExpirationMs;

  public JwtServiceProvider(
      RequestMetadata requestMetadata, @Value("${app.jwt.secret}") String jwtSecret,
      @Value("${app.jwt.expiration-ms}") long jwtExpirationMs) {
    this.requestMetadata = requestMetadata;
    this.jwtSecretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    this.jwtExpirationMs = jwtExpirationMs;
  }

  public TokenDetails generateToken(Authentication authentication) {
    UserDetailsDto userDetails = (UserDetailsDto) authentication.getPrincipal();

    String jti = Optional.ofNullable(userDetails.getPassword()).orElseGet(() -> UUID.randomUUID().toString());

    TokenDetails tokenDetails = TokenDetails.builder().username(userDetails.getUsername())
        .id(jti).issuedAt(new Date()).roles(userDetails.getRoles())
        .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
        .clientMetadata(requestMetadata.getClientInfo()).build();

    tokenDetails.setToken(Jwts.builder()
        .id(tokenDetails.getId())  // Include jti in the JWT
        .subject(tokenDetails.getUsername())
        .issuer("edu.ecom")
        .issuedAt(tokenDetails.getIssuedAt())
        .expiration(tokenDetails.getExpiration())
        .claim("fp", requestMetadata.generateClientFingerprint())
        .claim("authorities", userDetails.getAuthorities())
        .signWith(jwtSecretKey, SIG.HS256) // New signature method
        .compact());

    return tokenDetails;
  }

  public TokenDetails parseToken(String token) {
    TokenDetailsBuilder tokenDetails = TokenDetails.builder().token(token);
    try {
      // Parse with expiry check
      Claims claims = Jwts.parser()
          .verifyWith(jwtSecretKey)
          .build()
          .parseSignedClaims(token)
          .getPayload();
      populateTokenDetails(tokenDetails, claims, false);
    } catch (ExpiredJwtException e) { // Only for already expired tokens
      populateTokenDetails(tokenDetails, e.getClaims(), true);
    } catch (JwtException e) { // Handle other errors (invalid signature, malformed JWT)
      tokenDetails.genuine(false);
    }
    return tokenDetails.build();
  }

  private static void populateTokenDetails(TokenDetailsBuilder tokenDetails, Claims claims, boolean expired) {
    tokenDetails.claims(claims).username(claims.getSubject()).id(claims.getId())
        .expiration(claims.getExpiration()).genuine(true).expired(expired);
  }

  public Collection<? extends GrantedAuthority> extractAuthorities(Claims claims) {
    List<LinkedHashMap<String, String>> mapList = claims.get("authorities", List.class);
    return mapList.stream().map(m -> m.get("authority"))
        .map(SimpleGrantedAuthority::new)
        .toList();
  }

}