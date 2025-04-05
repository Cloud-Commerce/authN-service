package edu.ecom.authn.service;

import edu.ecom.authn.client.UserServiceClient;
import edu.ecom.authn.dto.AuthDetails;
import edu.ecom.authn.dto.ChangePasswordRequest;
import edu.ecom.authn.dto.CreateUserRequest;
import edu.ecom.authn.dto.LoginRequest;
import edu.ecom.authn.dto.TokenDetails;
import edu.ecom.authn.dto.UserServiceResponse;
import edu.ecom.authn.model.Role;
import io.jsonwebtoken.Claims;
import jakarta.servlet.ServletException;
import java.util.List;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

  private final UserServiceClient userServiceClient;
  private final TokenSessionManagementService tokenManagementService;
  private final JwtAuthHelper authHelper;

  @Autowired
  public AuthService(UserServiceClient userServiceClient,
      TokenSessionManagementService tokenManagementService, JwtAuthHelper authHelper) {
    this.userServiceClient = userServiceClient;
    this.tokenManagementService = tokenManagementService;
    this.authHelper = authHelper;
  }

  // Method to register a new user
  public String registerUser(CreateUserRequest userAuthRequest) {
    userAuthRequest.setRoles(List.of(Role.ROLE_CUSTOMER));
    ResponseEntity<UserServiceResponse> response = userServiceClient.registerUser(userAuthRequest);
    UserServiceResponse responseBody = Objects.requireNonNull(response.getBody());

    if (!response.getStatusCode().is2xxSuccessful()) {
      throw new RuntimeException("User registration failed: " + responseBody.error());
    }
    return responseBody.message();
  }

  public TokenDetails authenticateUser(LoginRequest request) {
    ResponseEntity<UserServiceResponse> response = userServiceClient.verifyCredentials(request);
    UserServiceResponse responseBody = Objects.requireNonNull(response.getBody());

    if (!response.getStatusCode().is2xxSuccessful()) {
      throw new BadCredentialsException(responseBody.error());
    }

    if (tokenManagementService.getActiveSessionCountForUser(request.getUsername()) >= 5) {
      throw new RuntimeException("Error: Maximum active sessions reached!");
    }

    Authentication authentication = authHelper.createAuthentication(responseBody);
    return tokenManagementService.createNewStatelessSession(authentication);
  }

  public TokenDetails reAuthenticateUser(String bearerToken) throws ServletException {
    String token = bearerToken.replace("Bearer ", "");
    Objects.requireNonNull(token);

    // Validate token and fetch profile...
    TokenDetails tokenDetails = authHelper.getVerifiedDetails();

    if(!tokenDetails.isExpired()) {
      throw new RuntimeException("Token still active!");
    }

    if (tokenManagementService.getActiveSessionCountForUser(tokenDetails.getClaims().getSubject()) >= 5) {
      throw new RuntimeException("Error: Maximum active sessions reached!");
    }

    Authentication authentication = authHelper.createAuthentication(tokenDetails);
    return tokenManagementService.createNewStatelessSession(authentication);
  }

  public void changePassword(ChangePasswordRequest request) {
    Claims claims = ((AuthDetails) SecurityContextHolder.getContext().getAuthentication().getDetails()).getClaims();
    request.setUsername(claims.getSubject());
    ResponseEntity<UserServiceResponse> response = userServiceClient.changePassword(request);
    UserServiceResponse responseBody = Objects.requireNonNull(response.getBody());

    if (!response.getStatusCode().is2xxSuccessful()) {
      throw new RuntimeException("Password change failed: " + responseBody.error());
    }
    tokenManagementService.invalidateAllTokensForUser(claims.getSubject());
  }

  public void logout() {
    Claims claims = ((AuthDetails) SecurityContextHolder.getContext().getAuthentication().getDetails()).getClaims();
    tokenManagementService.markAsBlacklisted(claims.getSubject(), claims.getId(), claims.getExpiration()); // Store in Redis/DB
  }
}
