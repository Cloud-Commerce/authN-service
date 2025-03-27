package edu.ecom.authn.entity;

import edu.ecom.authn.model.Role;
import edu.ecom.authn.model.UserRoleId;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Value;

@Entity
@Table(name = "user_roles")
@IdClass(UserRoleId.class) // For composite key
@Value
@NoArgsConstructor(force = true)
@AllArgsConstructor
public class UserRole {

  @Id
  @ManyToOne
  @JoinColumn(name = "user_id", nullable = false)
  User user;

  @Id
  @Enumerated(EnumType.STRING)
  @Column(columnDefinition = "role_enum", nullable = false)
  Role role;

  @Override
  public int hashCode() {
    return Objects.hash(role); // Only hash role, not user
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof UserRole userRole)) return false;
    return role == userRole.role; // Only compare role, not user
  }
}