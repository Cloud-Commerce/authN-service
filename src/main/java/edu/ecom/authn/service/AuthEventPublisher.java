package edu.ecom.authn.service;

import edu.ecom.common.events.CacheInvalidationEvent;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthEventPublisher {
    private final KafkaTemplate<String, CacheInvalidationEvent> kafkaTemplate;

    public void publishPasswordChangeEvent(List<String> ids) {
        CacheInvalidationEvent event = new CacheInvalidationEvent(
            UUID.randomUUID().toString(),
            "user_sessions",
            ids,
            "PASSWORD_CHANGE",
            Instant.now()
        );

        kafkaTemplate.send("auth.cache.invalidation", event);
        log.info("Published cache invalidation for user {}", ids);
    }
}