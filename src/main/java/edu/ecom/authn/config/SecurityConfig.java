package edu.ecom.authn.config;

import edu.ecom.authn.filter.JwtAuthenticationFilter;
import edu.ecom.authn.handler.CustomAccessDeniedHandler;
import edu.ecom.authn.handler.CustomAuthenticationEntryPoint;
import edu.ecom.authn.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthFilter) throws Exception {
    http
        // Disable CSRF for stateless JWT-based authentication
        .csrf(AbstractHttpConfigurer::disable)
        // Authorization rules
        .authorizeHttpRequests(this::getRequestMatcherRegistry)

        // Configure session management to be stateless
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

        // Exception handling
        .exceptionHandling(exception -> exception
            .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
            .accessDeniedHandler(new CustomAccessDeniedHandler())
        )

        // Logout configuration
        .logout(logout -> logout
            .logoutRequestMatcher(new AntPathRequestMatcher("/api/logout"))
            .clearAuthentication(true)
            .invalidateHttpSession(true)
        )

        // Add JWT filter
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  protected void getRequestMatcherRegistry(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorize) {
    authorize
        // Public endpoints
        .requestMatchers(getPublicEndpoints()).permitAll()

        // Admin endpoints
        .requestMatchers("/api/admin/**").hasAuthority(Role.ROLE_ADMIN.getAuthority())
        .requestMatchers("/api/inventory/**").hasAnyAuthority(
            Role.ROLE_INVENTORY_MANAGER.getAuthority(),
            Role.ROLE_ADMIN.getAuthority())

        // Authenticated access for other endpoints
        .anyRequest().authenticated();
  }

  @Bean("publicEndpoints")
  protected String[] getPublicEndpoints() {
   return new String[]{"/api/public/**", "/api/auth/**", "/actuator/**",
       "/v3/api-docs/**", "/swagger-ui/**"};
  }

  @Bean
  public AuthenticationManager authenticationManager(
      AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    // BCrypt password encoding with strength 12
    return new BCryptPasswordEncoder(12);
  }
}