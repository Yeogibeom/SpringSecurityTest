package example.springsecuritytest.controller;

import example.springsecuritytest.entity.Member;
import example.springsecuritytest.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;



@RestController
@RequestMapping("/member")
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;
    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody Member member) {
        memberService.getregister(member);
        return ResponseEntity.ok().build();
    }
}
