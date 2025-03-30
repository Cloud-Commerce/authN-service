package edu.ecom.authn.security.service;

import edu.ecom.authn.dto.TokenDetails;
import edu.ecom.authn.dto.TokenDetails.TokenDetailsBuilder;
import edu.ecom.authn.security.RequestMetadata;
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
import java.util.UUID;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
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
    UserDetails userDetails = (UserDetails) authentication.getPrincipal();

//    Map<String, Object> claims = new HashMap<>();
//    claims.put("roles", userDetails.getAuthorities().stream()
//        .map(GrantedAuthority::getAuthority)
//        .collect(Collectors.toList()));

    TokenDetails tokenDetails = TokenDetails.builder().username(userDetails.getUsername())
        .id(UUID.randomUUID().toString()).issuedAt(new Date()).state("Active")
        .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs)).build();

    tokenDetails.setToken(Jwts.builder()
        .id(tokenDetails.getId())  // Include jti in the JWT
        .subject(tokenDetails.getUsername())
        .issuer("edu.ecom.authn")
        .issuedAt(tokenDetails.getIssuedAt())
        .expiration(tokenDetails.getExpiration())
        .claim("authorities", userDetails.getAuthorities())
        .claims(requestMetadata.getClientInfo())
        .signWith(jwtSecretKey, SIG.HS512) // New signature method
        .compact());

    return tokenDetails;
  }

  public TokenDetails parseToken(String token) {
    TokenDetailsBuilder tokenDetails = TokenDetails.builder().token(token);
    try {
      // Parse with expiry check
      tokenDetails.claims(Jwts.parser()
              .verifyWith(jwtSecretKey)
              .build()
              .parseSignedClaims(token)
              .getPayload())
          .genuine(true)
          .expired(false);
    } catch (ExpiredJwtException e) {
      tokenDetails.claims(e.getClaims()).genuine(true).expired(true);
      System.out.println("Expired JWT: " + e.getMessage());
    } catch (JwtException e) {
      // Handle other errors (invalid signature, malformed JWT)
      tokenDetails.genuine(false);
      System.err.println("Invalid JWT: " + e.getMessage());
    }
    return tokenDetails.build();
  }

  public String extractUsername(String token) {
    return parseToken(token).getClaims().getSubject();
  }

  public Collection<? extends GrantedAuthority> extractAuthorities(Claims claims) {
    List<LinkedHashMap<String, String>> mapList = claims.get("authorities", List.class);
    return mapList.stream().map(m -> m.get("authority"))
        .map(SimpleGrantedAuthority::new)
        .toList();
  }

}