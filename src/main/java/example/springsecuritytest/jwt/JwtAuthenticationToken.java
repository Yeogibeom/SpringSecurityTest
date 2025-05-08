package example.springsecuritytest.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    public final String token;
    public final String principal;
    public JwtAuthenticationToken(String token) {
        super(null);  // 권한 정보는 이때 설정하지 않음
        this.token = token;
        this.principal = null;
        setAuthenticated(false);  // 인증되지 않은 상태로 설정
    }
    public JwtAuthenticationToken(Collection<? extends GrantedAuthority> authorities, String token, String principal) {
        super(authorities);
        this.token = token;
        this.principal = principal;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
