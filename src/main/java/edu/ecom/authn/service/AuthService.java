package edu.ecom.authn.service;

import edu.ecom.authn.client.UserServiceClient;
import edu.ecom.authn.dto.AuthDetails;
import edu.ecom.authn.dto.ChangePasswordRequest;
import edu.ecom.authn.dto.CreateUserRequest;
import edu.ecom.authn.dto.LoginRequest;
import edu.ecom.authn.dto.MessageResponse;
import edu.ecom.authn.dto.TokenDetails;
import edu.ecom.authn.dto.UserDetailsDto;
import edu.ecom.authn.model.Role;
import io.jsonwebtoken.Claims;
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
    ResponseEntity<?> response = userServiceClient.registerUser(userAuthRequest);

    if (!response.getStatusCode().is2xxSuccessful()) {
      throw new RuntimeException("User registration failed: " + response.getBody());
    }
    return ((MessageResponse) Objects.requireNonNull(response.getBody())).message();
  }

  public TokenDetails authenticateUser(LoginRequest request) {
    ResponseEntity<?> response = userServiceClient.getVerifiedUser(request);

    if (!response.getStatusCode().is2xxSuccessful()) {
      throw new BadCredentialsException((String) response.getBody());
    }

    if (tokenManagementService.getActiveSessionCountForUser(request.getUsername()) >= 5) {
      throw new RuntimeException("Error: Maximum active sessions reached!");
    }

    Authentication authentication = authHelper.createAuthentication((UserDetailsDto) Objects.requireNonNull(response.getBody()));
    return tokenManagementService.createNewStatelessSession(authentication);
  }

  public TokenDetails reAuthenticateUser(String bearerToken, boolean throwErrorIfActive) {
    String token = bearerToken.replace("Bearer ", "");
    Objects.requireNonNull(token);

    // Validate token and fetch profile...
    TokenDetails tokenDetails = authHelper.getVerifiedDetails();

    Authentication authentication = authHelper.createAuthentication(tokenDetails);
    SecurityContextHolder.getContext().setAuthentication(authentication);

    if(!tokenDetails.isExpired()) {
      if(throwErrorIfActive)
        throw new RuntimeException("Token still active!");
      else
        return tokenDetails;
    }

    if (tokenManagementService.getActiveSessionCountForUser(tokenDetails.getClaims().getSubject()) >= 5) {
      throw new RuntimeException("Error: Maximum active sessions reached!");
    }

    return tokenManagementService.createNewStatelessSession(authentication);
  }

  public void changePassword(ChangePasswordRequest request) {
    if(request.getOldPassword().equals(request.getNewPassword())) {
      throw new RuntimeException("New password cannot be the same as the old password!");
    }
    Claims claims = ((AuthDetails) SecurityContextHolder.getContext().getAuthentication().getDetails()).getClaims();
    request.setUsername(claims.getSubject());
    ResponseEntity<?> response = userServiceClient.changePassword(request);

    if (!response.getStatusCode().is2xxSuccessful()) {
      throw new RuntimeException("Password change failed: " + response.getBody());
    }
    tokenManagementService.invalidateAllTokensForUser(claims.getSubject());
  }

  public void logout() {
    Claims claims = ((AuthDetails) SecurityContextHolder.getContext().getAuthentication().getDetails()).getClaims();
    tokenManagementService.removeActiveSession(claims.getSubject(), claims.getId());
  }
}
