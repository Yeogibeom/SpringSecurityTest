package example.springsecuritytest.repository;

import example.springsecuritytest.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;



public interface MemberRepository extends JpaRepository<Member, Long> {
}
