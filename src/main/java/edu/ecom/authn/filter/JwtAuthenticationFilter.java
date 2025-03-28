package edu.ecom.authn.filter;

import edu.ecom.authn.security.UserDetailsImpl;
import edu.ecom.authn.util.JwtUtils;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtUtils jwtUtils;
  private final String[] publicEndpoints;

  @Autowired
  public JwtAuthenticationFilter(JwtUtils jwtUtils, String[] publicEndpoints) {
    this.jwtUtils = jwtUtils;
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
      String token = extractToken(request);
      if (token != null && jwtUtils.validateToken(token)) {
        String username = jwtUtils.getUsernameFromToken(token);
        Claims claims = jwtUtils.extractAllClaims(token);
        Collection<? extends GrantedAuthority> authorities = jwtUtils.extractAuthorities(claims);

        UserDetails userDetails = new UserDetailsImpl(claims.get("id", Long.class),
            username,
            null, // password not needed here
            authorities
        );

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
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

  private String extractToken(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
      return bearerToken.split(" ")[1];
    }
    return null;
  }
}
