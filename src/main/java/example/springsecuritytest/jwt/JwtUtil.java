package example.springsecuritytest.jwt;

import example.springsecuritytest.service.CustomUser;
import example.springsecuritytest.service.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.stream.Collectors;
import io.jsonwebtoken.io.Decoders;
@Component
@Getter
@Setter
public class JwtUtil {
    private static SecretKey key;

    // 생성자를 이용한 주입 방식으로 SecretKey 초기화 (빠름)
    public JwtUtil(@Value("${jwt.secret}") String secretKey) {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    // JWT 만들어주는 함수
    public static String createToken(Authentication auth) {
        var user = (CustomUserDetails)auth.getPrincipal();   //사용자 이름 , 비번x ,권한 , 닉네임 ㅇ
        var authorities = auth.getAuthorities().stream().map(a->a.getAuthority()).collect(Collectors.joining(","));
        String jwt = Jwts.builder()
                .claim("email", user.getEmail())
                .claim("displayName", user.getDisplayName())
                .claim("authorities", authorities)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 3600000)) //유효기간 10초
                .signWith(key)
                .compact();
        System.out.println("사용자 이메일 값"+user.getEmail());

        return jwt;
    }

    // JWT 까주는 함수
    public static Claims extractToken(String token) {
        Claims claims = Jwts.parser().verifyWith(key).build()
                .parseSignedClaims(token).getPayload();
        return claims;
    }

}