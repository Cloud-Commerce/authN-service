package edu.ecom.authn.util;

import edu.ecom.authn.security.UserDetailsImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JWTUtils {

  private final SecretKey jwtSecretKey;
  private final long jwtExpirationMs;

  public JWTUtils(
      @Value("${app.jwt.secret}") String jwtSecret,
      @Value("${app.jwt.expiration-ms}") long jwtExpirationMs) {
    // Convert the plain text secret to a secure key
    this.jwtSecretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    this.jwtExpirationMs = jwtExpirationMs;
  }

  public String generateToken(Authentication authentication) {
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

//    Map<String, Object> claims = new HashMap<>();
//    claims.put("roles", userDetails.getAuthorities().stream()
//        .map(GrantedAuthority::getAuthority)
//        .collect(Collectors.toList()));

    return Jwts.builder()
        .subject(userDetails.getUsername())
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
        .claim("id", userDetails.getId())
        .claim("authorities", userDetails.getAuthorities())
        .signWith(jwtSecretKey, Jwts.SIG.HS512) // New signature method
        .compact();
  }

  public String getUserNameFromJwtToken(String token) {
    return extractAllClaims(token).getSubject();
  }

  public boolean validateJwtToken(String authToken) {
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