package edu.ecom.authn.controller;

import edu.ecom.authn.dto.ChangePasswordRequest;
import edu.ecom.authn.dto.JwtResponse;
import edu.ecom.authn.dto.LoginRequest;
import edu.ecom.authn.dto.MessageResponse;
import edu.ecom.authn.dto.SignupRequest;
import edu.ecom.authn.service.UserDetailsServiceImpl;
import edu.ecom.authz.security.dto.AuthDetails;
import edu.ecom.authz.security.dto.TokenDetails;
import edu.ecom.authz.security.service.JwtAuthHelper;
import edu.ecom.authz.security.service.TokenSessionManagementService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.ServletException;
import jakarta.validation.Valid;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final AuthenticationManager authenticationManager;
  private final UserDetailsServiceImpl userDetailsService;
  private final TokenSessionManagementService tokenManagementService;
  private final JwtAuthHelper authHelper;

  @Autowired
  public AuthController(AuthenticationManager authenticationManager,
      UserDetailsServiceImpl userDetailsService, TokenSessionManagementService tokenManagementService,
      JwtAuthHelper authHelper) {
    this.authenticationManager = authenticationManager;
    this.userDetailsService = userDetailsService;
    this.tokenManagementService = tokenManagementService;
    this.authHelper = authHelper;
  }

  @PostMapping("/relogin")
  public ResponseEntity<?> reAuthenticateUser(@Valid @RequestHeader("Authorization") String bearerToken)
      throws ServletException {
    String token = bearerToken.replace("Bearer ", "");
    Objects.requireNonNull(token);
    // Validate token and fetch profile...
    TokenDetails tokenDetails = authHelper.getVerifiedDetails();

    if(!tokenDetails.isExpired()) {
      return ResponseEntity.ok().body(new MessageResponse("Token still active!"));
    }

    Authentication authentication = authHelper.createAuthentication(tokenDetails);

    if (tokenManagementService.getActiveSessionCountForUser(tokenDetails.getClaims().getSubject()) >= 5) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Maximum active sessions reached!"));
    }

    TokenDetails newSession = tokenManagementService.createNewStatelessSession(authentication);

    return ResponseEntity.accepted().body(new JwtResponse(newSession.getToken()));
  }

  @PostMapping("/login")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    if (tokenManagementService.getActiveSessionCountForUser(loginRequest.getUsername()) >= 5) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Maximum active sessions reached!"));
    }

    TokenDetails tokenDetails = tokenManagementService.createNewStatelessSession(authentication);

    return ResponseEntity.ok(new JwtResponse(tokenDetails.getToken()));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userDetailsService.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }

    userDetailsService.registerUser(signUpRequest.getUsername(), signUpRequest.getPassword());

    return ResponseEntity.accepted().body(new MessageResponse("User registered successfully!"));
  }

  @PostMapping("/change-password")
  public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
    Claims claims = ((AuthDetails) SecurityContextHolder.getContext().getAuthentication().getDetails()).getClaims();
    userDetailsService.changePassword(claims.getSubject(), request.getOldPassword(), request.getNewPassword());
    tokenManagementService.invalidateAllTokensForUser(claims.getSubject());

    return ResponseEntity.ok("Password updated successfully");
  }

  @PostMapping("/logout")
  public ResponseEntity<?> logout() {
    Claims claims = ((AuthDetails) SecurityContextHolder.getContext().getAuthentication().getDetails()).getClaims();
    tokenManagementService.markAsBlacklisted(claims.getSubject(), claims.getId(), claims.getExpiration()); // Store in Redis/DB
    return ResponseEntity.ok("Logged out successfully");
  }
}
