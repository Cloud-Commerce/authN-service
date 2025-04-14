package edu.ecom.authn.controller;

import edu.ecom.authn.dto.ChangePasswordRequest;
import edu.ecom.authn.dto.CreateUserRequest;
import edu.ecom.authn.dto.JwtResponse;
import edu.ecom.authn.dto.LoginRequest;
import edu.ecom.authn.dto.MessageResponse;
import edu.ecom.authn.dto.TokenDetails;
import edu.ecom.authn.service.AuthService;
import feign.FeignException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final AuthService authService;

  @Autowired
  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody CreateUserRequest userAuthRequest) {
    try {
      String response = authService.registerUser(userAuthRequest);
      return ResponseEntity.accepted().body(new MessageResponse(response));
    } catch(FeignException e) {
      return ResponseEntity.badRequest().body(new MessageResponse(e.contentUTF8()));
    } catch(Exception e) {
      return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
    }
  }

  @PostMapping("/login")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest request) {
    try {
      TokenDetails tokenDetails = authService.authenticateUser(request);
      return ResponseEntity.ok(new JwtResponse(tokenDetails.getToken()));
    } catch(FeignException e) {
      return ResponseEntity.badRequest().body(new MessageResponse(e.contentUTF8()));
    } catch(Exception e) {
      return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
    }
  }

  @PostMapping("/relogin")
  public ResponseEntity<?> reAuthenticateUser(@Valid @RequestHeader("Authorization") String bearerToken) {
    try {
      TokenDetails newSession = authService.reAuthenticateUser(bearerToken, true);
    return ResponseEntity.accepted().body(new JwtResponse(newSession.getToken()));
    } catch(Exception e) {
      return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
    }
  }

  @PostMapping("/verify")
  public ResponseEntity<?> verifyToken(@Valid @RequestHeader("Authorization") String bearerToken) {
    try {
      TokenDetails newSession = authService.reAuthenticateUser(bearerToken, false);
      newSession.setRoles(SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream().map(
          GrantedAuthority::getAuthority).toList());
      return ResponseEntity.accepted().body(newSession);
    } catch(Exception e) {
      return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
    }
  }

  @PostMapping("/change-password")
  public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
    try {
      authService.changePassword(request);
      return ResponseEntity.ok(new MessageResponse("Password updated successfully"));
    } catch(FeignException e) {
      return ResponseEntity.badRequest().body(new MessageResponse(e.contentUTF8()));
    } catch(Exception e) {
      return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
    }
  }

  @PostMapping("/logout")
  public ResponseEntity<?> logout() {
    try {
      authService.logout();
      return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    } catch(Exception e) {
      return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
    }
  }
}
