package edu.ecom.authn.handler;

import edu.ecom.authn.client.UserServiceClient;
import edu.ecom.authn.dto.ChangePasswordRequest;
import edu.ecom.authn.dto.CreateUserRequest;
import edu.ecom.authn.dto.LoginRequest;
import edu.ecom.authn.dto.UserServiceResponse;
import jakarta.ws.rs.ServiceUnavailableException;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
public class UserServiceFallback implements UserServiceClient {

  @Override
  public ResponseEntity<UserServiceResponse> registerUser(CreateUserRequest request) {
    throw new ServiceUnavailableException("User service down");
  }

  @Override
  public ResponseEntity<UserServiceResponse> verifyCredentials(LoginRequest request) {
    throw new ServiceUnavailableException("User service down");
  }

  @Override
  public ResponseEntity<UserServiceResponse> changePassword(ChangePasswordRequest request) {
    throw new ServiceUnavailableException("User service down");
  }
}