package com.example.spring.service.MemberService;

import com.example.spring.domain.Member;
import com.example.spring.web.dto.MemberDTO.MemberRequestDTO;

public interface MemberCommandService {

    // 일반 회원가입
    Member joinMember(MemberRequestDTO.JoinDto request);

}
