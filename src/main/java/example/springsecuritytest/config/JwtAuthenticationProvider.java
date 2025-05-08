package example.springsecuritytest.config;

import example.springsecuritytest.jwt.JwtAuthenticationToken;
import io.jsonwebtoken.Claims;
import example.springsecuritytest.jwt.JwtUtil;
import example.springsecuritytest.service.CustomUserDetails;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Arrays;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // "authentication.getCredentials()"에서 토큰을 가져옵니다.
        String token = (String) authentication.getCredentials();

        // JWT 토큰에서 Claims를 추출합니다.
        Claims claims = JwtUtil.extractToken(token);

        if (claims == null) {
            return null;
        }

        // JWT에서 authorities 값을 가져와서 SimpleGrantedAuthority로 변환
        String authoritiesString = (String) claims.get("authorities");
        List<SimpleGrantedAuthority> authorities = authoritiesString == null ? List.of() :
                Arrays.stream(authoritiesString.split(","))
                        .map(SimpleGrantedAuthority::new)
                        .toList();

        // CustomUserDetails 객체를 생성합니다.
        CustomUserDetails customUserDetails = new CustomUserDetails(
                claims.get("email").toString(),
                "none",  // 비밀번호는 사용하지 않으므로 "none"으로 설정
                claims.get("displayName").toString(),
                authorities
        );

        // JwtAuthenticationToken을 반환합니다.
        return new JwtAuthenticationToken(authorities, token, customUserDetails.getUsername());  // JwtAuthenticationToken을 인증된 상태로 설정합니다.
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
