package edu.ecom.authn.model;

public enum Role {
  ROLE_CUSTOMER,
  ROLE_ADMIN,
  ROLE_INVENTORY_MANAGER;

  public String getAuthority() {
    return name();
  }
}