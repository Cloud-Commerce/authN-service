package edu.ecom.authn.repository;

import edu.ecom.authn.entity.UserRole;
import edu.ecom.authn.model.UserRoleId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRoleRepository extends JpaRepository<UserRole, UserRoleId> {

  @Modifying
  @Query(value = "INSERT INTO user_roles (role, user_id) VALUES (CAST(:role AS role_enum), :userId)", nativeQuery = true)
  void insertUserRole(@Param("role") String role, @Param("userId") Long userId);

}
