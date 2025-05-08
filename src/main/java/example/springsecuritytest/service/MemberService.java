package example.springsecuritytest.service;

import example.springsecuritytest.entity.Member;
import example.springsecuritytest.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;



@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    public ResponseEntity<Object> getregister (Member member) {
        var password = passwordEncoder.encode(member.getPassword());
        member.setPassword(password);
        memberRepository.save(member);
     return ResponseEntity.ok("회원가입 성공");
    }
}
