package edu.ecom.authn.client;

import edu.ecom.authn.config.FeignConfig;
import edu.ecom.authn.dto.ChangePasswordRequest;
import edu.ecom.authn.dto.CreateUserRequest;
import edu.ecom.authn.dto.LoginRequest;
import edu.ecom.authn.dto.UserServiceResponse;
import edu.ecom.authn.handler.UserServiceFallback;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", path = "/api",
    configuration = FeignConfig.class, fallback = UserServiceFallback.class)
public interface UserServiceClient {

  @PostMapping("/users")
  ResponseEntity<UserServiceResponse> registerUser(@RequestBody CreateUserRequest request);

  @PostMapping("/internal/auth/verify")
  ResponseEntity<UserServiceResponse> verifyCredentials(@RequestBody LoginRequest request);

  @PostMapping("/internal/auth/change-password")
  ResponseEntity<UserServiceResponse> changePassword(@RequestBody ChangePasswordRequest request);
}