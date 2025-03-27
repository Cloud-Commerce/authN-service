package edu.ecom.authn.entity;

import edu.ecom.authn.model.Role;
import jakarta.persistence.*;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true)
  private String username;

  @Column(nullable = false)
  private String password;

  @Column(name = "created_at", updatable = false)
  @Temporal(TemporalType.TIMESTAMP)
  private final Date createdAt = new Date();

  @Column(name = "updated_at")
  @Temporal(TemporalType.TIMESTAMP)
  private final Date updatedAt = new Date();

  @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<UserRole> roles = new HashSet<>();

  @Override
  public int hashCode() {
    return Objects.hash(id, username); // Only hash immutable fields
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof User user)) return false;
    return Objects.equals(id, user.id) &&
        Objects.equals(username, user.username);
  }

  // Helper methods
  public void addRole(Role role) {
    if (this.roles == null) {
      this.roles = new HashSet<>();
    }
    this.roles.add(new UserRole(this, role));
  }

  public void removeRole(Role role) {
    roles.removeIf(userRole -> userRole.getRole() == role);
  }

  // UserDetails interface methods
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Collections.emptyList();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

}