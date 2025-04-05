package edu.ecom.authn.dto;

import org.springframework.security.core.userdetails.UserDetails;

public record UserServiceResponse(boolean success, UserDetails userDetails, String message, String error) {}