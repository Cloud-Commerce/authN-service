package edu.ecom.authn.service;

import edu.ecom.authn.entity.User;
import edu.ecom.authn.model.Role;
import edu.ecom.authn.repository.UserRepository;
import edu.ecom.authn.security.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  @Override
  public UserDetails loadUserByUsername(String username) {
    return userRepository.findByUsername(username).map(UserDetailsImpl::build)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }

  public void registerUser(String username, String password) {
    if (userRepository.existsByUsername(username)) {
      throw new IllegalArgumentException("Username already exists");
    }

    User user = new User(username, passwordEncoder.encode(password));
    user.addRole(Role.ROLE_CUSTOMER);
    userRepository.save(user);
  }

  public Boolean existsByUsername(String username) {
    return userRepository.existsByUsername(username);
  }
}