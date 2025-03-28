package edu.ecom.authn.controller;

import edu.ecom.authn.dto.AuthDetails;
import edu.ecom.authn.dto.ChangePasswordRequest;
import edu.ecom.authn.dto.JwtResponse;
import edu.ecom.authn.dto.LoginRequest;
import edu.ecom.authn.dto.MessageResponse;
import edu.ecom.authn.dto.SignupRequest;
import edu.ecom.authn.dto.TokenDetails;
import edu.ecom.authn.security.service.JwtServiceProvider;
import edu.ecom.authn.security.service.TokenManagementService;
import edu.ecom.authn.service.UserDetailsServiceImpl;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
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
  private final JwtServiceProvider jwtServiceProvider;
  private final UserDetailsServiceImpl userDetailsService;
  private final TokenManagementService tokenManagementService;

  @Autowired
  public AuthController(AuthenticationManager authenticationManager, JwtServiceProvider jwtServiceProvider,
      UserDetailsServiceImpl userDetailsService, TokenManagementService tokenManagementService) {
    this.authenticationManager = authenticationManager;
    this.jwtServiceProvider = jwtServiceProvider;
    this.userDetailsService = userDetailsService;
    this.tokenManagementService = tokenManagementService;
  }

  @PostMapping("/login")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    if (tokenManagementService.getActiveSessionCountForUser(loginRequest.getUsername()) >= 5) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Maximum active sessions reached!"));
    }

    TokenDetails tokenDetails = jwtServiceProvider.generateToken(authentication);

    tokenManagementService.addActiveSession(tokenDetails);

    return ResponseEntity.ok(new JwtResponse(tokenDetails.getToken()));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userDetailsService.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }

    userDetailsService.registerUser(signUpRequest.getUsername(), signUpRequest.getPassword());

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  @PostMapping("/change-password")
  public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request,
      @RequestHeader("Authorization") String token) {

    String username = jwtServiceProvider.extractUsername(token);

    userDetailsService.changePassword(username, request.getOldPassword(), request.getNewPassword());
    tokenManagementService.invalidateAllTokensForUser(username);

    return ResponseEntity.ok("Password updated successfully");
  }

  @PostMapping("/logout")
  public ResponseEntity<?> logout() {
    Claims claims = ((AuthDetails) SecurityContextHolder.getContext().getAuthentication().getDetails()).getClaims();
    tokenManagementService.markAsBlacklisted(claims.getId(), claims.getExpiration()); // Store in Redis/DB
    return ResponseEntity.ok("Logged out successfully");
  }
}
