package edu.ecom.authn.client;

import edu.ecom.authn.config.FeignConfig;
import edu.ecom.authn.dto.ChangePasswordRequest;
import edu.ecom.authn.dto.CreateUserRequest;
import edu.ecom.authn.dto.LoginRequest;
import edu.ecom.authn.dto.MessageResponse;
import edu.ecom.authn.dto.UserDetailsDto;
import edu.ecom.authn.handler.UserServiceFallback;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", path = "/api/internal/auth/",
    configuration = FeignConfig.class, fallback = UserServiceFallback.class)
public interface UserServiceClient {

  @PostMapping("/add-user")
  ResponseEntity<MessageResponse> registerUser(@RequestBody CreateUserRequest request);

  @PostMapping("/verified-user")
  ResponseEntity<UserDetailsDto> getVerifiedUser(@RequestBody LoginRequest request);

  @PostMapping("/change-password")
  ResponseEntity<MessageResponse> changePassword(@RequestBody ChangePasswordRequest request);
}