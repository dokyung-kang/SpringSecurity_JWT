package com.example.spring.service.MemberService;

import com.example.spring.domain.Member;
import com.example.spring.web.dto.MemberDTO.MemberRequestDTO;
import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;

public interface MemberCommandService {

    // 일반 회원가입
    Member joinMember(MemberRequestDTO.JoinDto request);

    // 로그인
    MemberResponseDTO.LoginResultDTO loginMember(MemberRequestDTO.LoginRequestDTO request);
}
