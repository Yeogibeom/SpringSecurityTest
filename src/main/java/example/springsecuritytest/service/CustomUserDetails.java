package example.springsecuritytest.service;

import example.springsecuritytest.entity.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class CustomUserDetails  implements UserDetails {
    private final Member member;
    private final List<SimpleGrantedAuthority> authorities;

    public CustomUserDetails(Member member, List<SimpleGrantedAuthority> authorities) {
        this.member = member;
        this.authorities = authorities;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }
    public String getEmail() {
        return member.getEmail();
    }

    // 새 생성자 (에러 해결용)
    public CustomUserDetails(String email, String password, String displayName, List<SimpleGrantedAuthority> authorities) {
        this.member = new Member(); // 기본 생성자 있어야 함
        this.member.setEmail(email);
        this.member.setPassword(password);
        this.member.setDisplayName(displayName);
        this.authorities = authorities;
    }
    public String getDisplayName() {
        return member.getDisplayName();
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return "";
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
