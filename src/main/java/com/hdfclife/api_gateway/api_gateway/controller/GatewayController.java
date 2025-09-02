package com.hdfclife.api_gateway.api_gateway.controller;

import com.hdfclife.api_gateway.api_gateway.dto.ErrorResponse;
import com.hdfclife.api_gateway.api_gateway.dto.GenericProxyResponse;
import com.hdfclife.api_gateway.api_gateway.dto.LoginRequest;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/auth")
public class GatewayController {
    private static final Logger logger = LoggerFactory.getLogger(GatewayController.class);
    private final RestTemplate restTemplate;
    private final String authServiceUrl;

    public GatewayController(RestTemplate restTemplate, @Value("${auth.service.url}") String authServiceUrl) {
        this.restTemplate = restTemplate;
        this.authServiceUrl = authServiceUrl;
    }

    @PostMapping("/login")
    @RateLimiter(name = "authRateLimiter", fallbackMethod = "rateLimiterFallback")
    @CircuitBreaker(name = "authCircuitBreaker", fallbackMethod = "circuitBreakerFallback")
    // CHANGED: The return type is now more specific.
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        logger.info("Gateway forwarding login request for user: {}", loginRequest.getUsername());
        String loginUrl = authServiceUrl + "/login";

        try {
            // CHANGED: We now ask RestTemplate to convert the successful response to our GenericProxyResponse.
            ResponseEntity<GenericProxyResponse> responseEntity =
                    restTemplate.postForEntity(loginUrl, loginRequest, GenericProxyResponse.class);

            // We return the body of that response, letting Spring build a clean, new response for the client.
            return ResponseEntity.ok(responseEntity.getBody().getProperties());

        } catch (HttpClientErrorException e) {
            // This logic remains the same.
            logger.warn("Client error from auth-service: {} for user {}", e.getStatusCode(), loginRequest.getUsername());
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (ResourceAccessException e) {
            logger.error("Network error connecting to auth-service: {}", e.getMessage());
            throw e;
        }
    }

    @PostMapping("/logout")
    // CHANGED: The return type is now more specific.
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authorizationHeader) {
        logger.info("Gateway forwarding logout request.");
        String logoutUrl = authServiceUrl + "/logout";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", authorizationHeader);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            // CHANGED: We deserialize the response and then re-serialize it.
            ResponseEntity<GenericProxyResponse> responseEntity =
                    restTemplate.exchange(logoutUrl, HttpMethod.POST, entity, GenericProxyResponse.class);

            return ResponseEntity.ok(responseEntity.getBody().getProperties());

        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }

    // Fallback methods remain unchanged.
    public ResponseEntity<ErrorResponse> rateLimiterFallback(LoginRequest loginRequest, Throwable t) {
        logger.warn("Rate limit exceeded for login attempt by user: {}. Cause: {}", loginRequest.getUsername(), t.getMessage());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(new ErrorResponse("Too many login attempts. Please try again later."));
    }

    public ResponseEntity<ErrorResponse> circuitBreakerFallback(LoginRequest loginRequest, Throwable t) {
        logger.error("Circuit breaker is open for auth-service. Login blocked for user: {}. Failure: {}", loginRequest.getUsername(), t.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(new ErrorResponse("Authentication service is temporarily unavailable. Please try again later."));
    }
}