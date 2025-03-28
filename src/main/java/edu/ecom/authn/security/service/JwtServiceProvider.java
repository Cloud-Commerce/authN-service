package edu.ecom.authn.security.service;

import edu.ecom.authn.dto.TokenDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
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

  private final SecretKey jwtSecretKey;
  private final long jwtExpirationMs;

  public JwtServiceProvider(
      @Value("${app.jwt.secret}") String jwtSecret,
      @Value("${app.jwt.expiration-ms}") long jwtExpirationMs) {
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
        .signWith(jwtSecretKey, SIG.HS512) // New signature method
        .compact());

    return tokenDetails;
  }

  public String extractUsername(String token) {
    return extractAllClaims(token).getSubject();
  }

  public boolean validateToken(String authToken) {
    try {
      Jwts.parser()
          .verifyWith(jwtSecretKey)
          .build()
          .parseSignedClaims(authToken);
      return true;
    } catch (SecurityException | JwtException | IllegalArgumentException e) {
      log.error("Invalid JWT token: {}", e.getMessage());
      return false;
    }
  }

  public Collection<? extends GrantedAuthority> extractAuthorities(Claims claims) {
    List<String> authorities = claims.get("authorities", List.class);
    return authorities.stream()
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());
  }

  public Claims extractAllClaims(String token) {
    return Jwts.parser()
        .verifyWith(jwtSecretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }
}