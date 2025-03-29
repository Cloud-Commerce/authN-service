package edu.ecom.authn.security;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import eu.bitwalker.useragentutils.*;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

@Component
@RequestScope
public class RequestMetadata {

  private final HttpServletRequest request;

  public RequestMetadata(HttpServletRequest request) {
    this.request = request;
  }

  public Map<String, Object> getClientInfo() {
    Map<String, Object> metadata = new HashMap<>();

    // 1. Device/Browser Info (Using User-Agent)
    UserAgent userAgent = UserAgent.parseUserAgentString(request.getHeader("User-Agent"));
    metadata.put("deviceType", userAgent.getOperatingSystem().getDeviceType().getName()); // MOBILE, TABLET, etc.
    metadata.put("browser", userAgent.getBrowser().getName()); // Chrome, Firefox
    metadata.put("os", userAgent.getOperatingSystem().getName()); // Windows, Android

    // 2. IP Address
    metadata.put("ip", getClientIp(request));

    // 3. Request Headers (Optional)
    metadata.put("userAgentRaw", request.getHeader("User-Agent"));
    metadata.put("acceptLanguage", request.getHeader("Accept-Language"));

    return metadata;
  }

  private static String getClientIp(HttpServletRequest request) {
    String ip = request.getHeader("X-Forwarded-For");
    if (ip == null || ip.isEmpty()) {
      ip = request.getRemoteAddr();
    }
    return ip;
  }
}