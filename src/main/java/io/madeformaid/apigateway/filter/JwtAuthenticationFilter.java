package io.madeformaid.apigateway.filter;


import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.madeformaid.apigateway.util.JwtTokenProvider;
import io.madeformaid.shared.config.AuthProperties;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final AuthProperties authProperties;

    public JwtAuthenticationFilter(
            JwtTokenProvider jwtTokenProvider,
            AuthProperties authProperties
    ) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.authProperties = authProperties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (authProperties.getWhitelist().stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange); // 화이트리스트에 있는 경로는 필터를 통과시킴
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                DecodedJWT jwt = jwtTokenProvider.validateAndGetDecodedJwt(token);

                // 사용자 정보 추출
                String accountId = jwt.getSubject();
                String userId = jwt.getClaim("userId").asString();
                String shopId = jwt.getClaim("shopId").asString();
                List<String> roles = Optional.ofNullable(jwt.getClaim("roles").asList(String.class))
                        .orElse(Collections.emptyList());

                // 헤더에 사용자 정보 추가
                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("X-Account-Id", accountId)
                        .header("X-User-Id", userId)
                        .header("X-Shop-Id", shopId)
                        .header("X-User-Roles", String.join(",", roles))
                        .build();

                // 인증 객체 생성 및 SecurityContext 설정
                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, authorities);

                ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
                return chain.filter(mutatedExchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
            } catch (JWTVerificationException e) {
                return unauthorized(exchange, "Invalid JWT token");
            }
        }

        return unauthorized(exchange, "Missing or invalid Authorization header");
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
