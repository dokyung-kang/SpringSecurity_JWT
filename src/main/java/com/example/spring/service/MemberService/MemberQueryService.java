package com.example.spring.service.MemberService;

import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;
import jakarta.servlet.http.HttpServletRequest;

public interface MemberQueryService {

    // 내 정보 조회
    MemberResponseDTO.MemberInfoDTO getMemberInfo(HttpServletRequest request);
}
