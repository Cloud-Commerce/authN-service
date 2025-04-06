package edu.ecom.authn.handler;

import edu.ecom.authn.client.UserServiceClient;
import edu.ecom.authn.dto.ChangePasswordRequest;
import edu.ecom.authn.dto.CreateUserRequest;
import edu.ecom.authn.dto.LoginRequest;
import edu.ecom.authn.dto.MessageResponse;
import edu.ecom.authn.dto.UserDetailsDto;
import jakarta.ws.rs.ServiceUnavailableException;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
public class UserServiceFallback implements UserServiceClient {

  @Override
  public ResponseEntity<MessageResponse> registerUser(CreateUserRequest request) {
    throw new ServiceUnavailableException("User service down");
  }

  @Override
  public ResponseEntity<UserDetailsDto> getVerifiedUser(LoginRequest request) {
    throw new ServiceUnavailableException("User service down");
  }

  @Override
  public ResponseEntity<MessageResponse> changePassword(ChangePasswordRequest request) {
    throw new ServiceUnavailableException("User service down");
  }
}