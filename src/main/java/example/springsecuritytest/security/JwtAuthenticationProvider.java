package example.springsecuritytest.security;

import example.springsecuritytest.jwt.JwtUtil;
import example.springsecuritytest.service.CustomUserDetails;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
           String token = (String) authentication.getCredentials();
           Claims claims = JwtUtil.extractToken(token);

           if (claims == null) {
               return null;
           }
           String authoritiesString = (String) claims.get("authorities");
        List<SimpleGrantedAuthority> authorities = authoritiesString == null ? List.of() :
                Arrays.stream(authoritiesString.split(","))
                        .map(SimpleGrantedAuthority::new)
                        .toList();

        CustomUserDetails customUserDetails = new CustomUserDetails(
                claims.get("email").toString(),
                "none",
                claims.get("displayName").toString(),
                authorities
        );
        return new UsernamePasswordAuthenticationToken(customUserDetails, token, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
