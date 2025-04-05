package edu.ecom.authn.config;

import edu.ecom.authn.service.HmacSigningService;
import feign.FeignException;
import feign.Request;
import feign.RequestInterceptor;
import feign.Retryer;
import feign.Target;
import feign.codec.ErrorDecoder;
import jakarta.ws.rs.BadRequestException;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignConfig {

    private final HmacSigningService hmacService;
    private final String serviceId;

    @Autowired
    public FeignConfig(HmacSigningService hmacService, @Value("${spring.application.name}") String serviceId) {
        this.hmacService = hmacService;
        this.serviceId = serviceId;
    }

    @Bean
    public RequestInterceptor hmacSigningInterceptor() {
        return template -> {
            String timestamp = String.valueOf(Instant.now().getEpochSecond());
            Target<?> feignTarget = template.feignTarget();
            String basePath = feignTarget.url().replaceFirst("^.*?" + Pattern.quote(feignTarget.name()), "");
            String message = hmacService.generateMessage(serviceId, timestamp, basePath + template.path(), template.method());
            String signature = hmacService.calculateSignature(message);

            template.header("X-Auth-Signature", signature);
            template.header("X-Auth-Timestamp", timestamp);
            template.header("X-Service-ID", serviceId);
        };
    }

    // 1. HTTP Timeouts
    @Bean
    public Request.Options feignRequestOptions() {
        return new Request.Options(
            5, TimeUnit.SECONDS,   // Connect timeout
            10, TimeUnit.SECONDS,   // Read timeout
            false
        );
    }

    // 2. Retry Configuration
    @Bean
    public Retryer feignRetryer() {
        return new Retryer.Default(
            1000,     // Initial interval (1s)
            5000,     // Max interval (5s)
            3         // Max attempts
        );
    }
}