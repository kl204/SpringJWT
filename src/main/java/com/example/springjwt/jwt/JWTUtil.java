package com.example.springjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// jwt o.12.3 버전임
// 11과 12가 메서드가 매우 다르므로 취사 선택해서 잘 사용하여야함
@Component
public class JWTUtil {

    private SecretKey secretKey;

    // 생성자를 통해서 SecretKey 객체를 만들어준다.
    public JWTUtil(@Value("${spring.jwt.secret}")String secret){

        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 토큰 검증 메서드 (secretKey, Role, Expired)
    public String getUsername(String token){

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username",String.class);
    }
    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }
    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    // 토큰 생성 메서드
    public String createJwt(String username, String role, Long expireMs){

        return Jwts.builder()
                .claim("username",username)
                .claim("role", role)
                // 토큰이 언제 발행됐는지 발행 시간을 넣는 메서드
                .issuedAt(new Date(System.currentTimeMillis()))
                // 이 토큰이 언제 소멸 될 것인지
                .expiration(new Date(System.currentTimeMillis() + expireMs))
                .signWith(secretKey)
                .compact();
    }

}

// jwt 0.11.5 버전 메서드
//@Component
//public class JWTUtil {
//
//    private Key key;
//
//    public JWTUtil(@Value("${spring.jwt.secret}")String secret) {
//
//
//        byte[] byteSecretKey = Decoders.BASE64.decode(secret);
//        key = Keys.hmacShaKeyFor(byteSecretKey);
//    }
//
//    public String getUsername(String token) {
//
//        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().get("username", String.class);
//    }
//
//    public String getRole(String token) {
//
//        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().get("role", String.class);
//    }
//
//    public Boolean isExpired(String token) {
//
//        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getExpiration().before(new Date());
//    }
//
//    public String createJwt(String username, String role, Long expiredMs) {
//
//        Claims claims = Jwts.claims();
//        claims.put("username", username);
//        claims.put("role", role);
//
//        return Jwts.builder()
//                .setClaims(claims)
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .setExpiration(new Date(System.currentTimeMillis() + expiredMs))
//                .signWith(key, SignatureAlgorithm.HS256)
//                .compact();
//    }
//}
