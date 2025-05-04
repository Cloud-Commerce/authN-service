package edu.ecom.authn.service;

import edu.ecom.authn.dto.TokenDetails;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class TokenSessionManagementService {

  private final RedisTemplate<String, TokenDetails> redisTemplate;
  private final edu.ecom.authn.service.JwtServiceProvider jwtServiceProvider;

  @Autowired
  public TokenSessionManagementService(RedisTemplate<String, TokenDetails> redisTemplate,
      JwtServiceProvider jwtServiceProvider) {
    this.redisTemplate = redisTemplate;
    this.jwtServiceProvider = jwtServiceProvider;
  }

  public void addActiveSession(TokenDetails tokenDetails) {
    String activeSessionKey = getActiveSessionKeyForUser(tokenDetails.getUsername(), tokenDetails.getId());
    if(redisTemplate.hasKey(activeSessionKey))
      redisTemplate.expire(activeSessionKey, 7, TimeUnit.DAYS);
    else
      redisTemplate.opsForValue().set(activeSessionKey, tokenDetails, 7, TimeUnit.DAYS);
  }

  private static String getActiveSessionKeyForUser(String username, String jti) {
    return String.format("user:sessions:%s:%s", username, jti);
  }

  public void removeActiveSession(String username, String jti) {
    redisTemplate.delete(getActiveSessionKeyForUser(username, jti));
  }

  public boolean isSessionActive(String username, String jti) {
    return redisTemplate.hasKey(getActiveSessionKeyForUser(username, jti));
  }

  public int getActiveSessionCountForUser(String username) {
    return Objects.requireNonNull(getKeysByPrefix(getActiveSessionKeyForUser(username, ""))).size();
  }

  public void invalidateAllTokensForUser(String username) {
    List<String> activeSessionKeysByPrefix = getKeysByPrefix(getActiveSessionKeyForUser(username, ""));
    activeSessionKeysByPrefix.stream().map(redisTemplate.opsForValue()::getAndDelete)
        .filter(Objects::nonNull).forEach(tokenDetails -> removeActiveSession(username, tokenDetails.getId()));
  }

  private Map<String, TokenDetails> getKeyValuesByPrefix(String prefix) {
    List<String> keys = getKeysByPrefix(prefix);
    return Objects.requireNonNull(redisTemplate.opsForValue().multiGet(keys)).stream()
        .collect(Collectors.toMap(v -> getActiveSessionKeyForUser(v.getUsername(), v.getId()), tokenDetails -> tokenDetails));
  }

  private List<String> getKeysByPrefix(String prefix) {
    List<String> keys = new ArrayList<>();
    ScanOptions scanOptions = ScanOptions.scanOptions()
        .match(prefix + "*") // Prefix pattern
        .count(10) // Batch size (adjust based on Redis size)
        .build();

    // Iterate using a Cursor
    try (Cursor<String> cursor = redisTemplate.scan(scanOptions)) {
      while (cursor.hasNext()) {
        keys.add(cursor.next());
      }
    } catch (Exception e) {
      throw new RuntimeException("Failed to scan Redis keys", e);
    }
    return keys;
  }

  public TokenDetails createNewStatelessSession(Authentication authentication) {
    TokenDetails tokenDetails = jwtServiceProvider.generateToken(authentication);
    addActiveSession(tokenDetails);
    return tokenDetails;
  }
}