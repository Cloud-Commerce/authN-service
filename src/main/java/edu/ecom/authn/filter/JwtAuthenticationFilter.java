package edu.ecom.authn.filter;

import edu.ecom.authn.dto.TokenDetails;
import edu.ecom.authn.handler.CustomAuthenticationEntryPoint;
import edu.ecom.authn.service.JwtAuthHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtAuthHelper authHelper;
  private final String[] publicEndpoints;
  private final AuthenticationEntryPoint authEntryPointHandler = new CustomAuthenticationEntryPoint();

  @Autowired
  public JwtAuthenticationFilter(JwtAuthHelper authHelper, String[] publicEndpoints) {
    this.authHelper = authHelper;
    this.publicEndpoints = publicEndpoints;
  }

  @Override
  protected void doFilterInternal(@NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {
    if (!requiresAuthentication(request)) {
      filterChain.doFilter(request, response);
      return;
    }
    try {
      TokenDetails tokenDetails = authHelper.getVerifiedDetails();

      if(tokenDetails.isExpired()) {
        throw new SessionAuthenticationException("Expired Token");
      }

      Authentication authentication = authHelper.createAuthentication(tokenDetails);
      SecurityContextHolder.getContext().setAuthentication(authentication);
      filterChain.doFilter(request, response);
    } catch (AuthenticationException ex) {
      // Log the exception
      logger.error("Could not set user authentication in security context: {}", ex);
      authEntryPointHandler.commence(request, response, ex);
    } catch (Exception ex) {
      // Log the exception
      logger.error("Could not set user authentication in security context: {}", ex);
    }
  }

  private boolean requiresAuthentication(HttpServletRequest request) {
    return Arrays.stream(publicEndpoints).map(AntPathRequestMatcher::new)
        .noneMatch(requestMatcher -> requestMatcher.matches(request));
  }
}
