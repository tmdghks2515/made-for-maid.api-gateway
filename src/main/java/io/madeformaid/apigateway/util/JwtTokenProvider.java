package io.madeformaid.apigateway.util;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;


@Component
public class JwtTokenProvider {

    @Value("${auth.jwt.secret}")
    private String secret;

    private Algorithm algorithm;

    @PostConstruct
    public void init() {
        this.algorithm = Algorithm.HMAC256(secret);
    }

    public DecodedJWT validateAndGetDecodedJwt(String token) {
        return JWT.require(algorithm)
                .build()
                .verify(token);
    }
}
