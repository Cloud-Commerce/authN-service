package edu.ecom.authn.filter;

import edu.ecom.authn.dto.TokenDetails;
import edu.ecom.authn.service.JwtAuthHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtAuthHelper authHelper;
  private final String[] publicEndpoints;

  @Autowired
  public JwtAuthenticationFilter(JwtAuthHelper authHelper, String[] publicEndpoints) {
    this.authHelper = authHelper;
    this.publicEndpoints = publicEndpoints;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    if (!requiresAuthentication(request)) {
      filterChain.doFilter(request, response);
      return;
    }
    try {
      TokenDetails tokenDetails = authHelper.getVerifiedDetails();

      if(tokenDetails.isExpired()) {
        throw new ServletException("Expired Token"); // TODO - implementation to be changed
      }

      Authentication authentication = authHelper.createAuthentication(tokenDetails);
      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (Exception ex) {
      // Log the exception
      logger.error("Could not set user authentication in security context: {}", ex);
    }

    filterChain.doFilter(request, response);
  }

  private boolean requiresAuthentication(HttpServletRequest request) {
    return Arrays.stream(publicEndpoints).map(AntPathRequestMatcher::new)
        .noneMatch(requestMatcher -> requestMatcher.matches(request));
  }
}
