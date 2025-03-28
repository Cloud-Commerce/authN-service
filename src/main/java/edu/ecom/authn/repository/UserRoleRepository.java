package edu.ecom.authn.repository;

import edu.ecom.authn.entity.UserRole;
import edu.ecom.authn.model.UserRoleId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, UserRoleId> {}
