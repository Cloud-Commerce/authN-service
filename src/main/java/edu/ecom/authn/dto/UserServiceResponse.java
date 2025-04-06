package edu.ecom.authn.dto;

import edu.ecom.authn.model.UserDetailsImpl;

public record UserServiceResponse(boolean success, UserDetailsImpl userDetails, String message, String error) {}