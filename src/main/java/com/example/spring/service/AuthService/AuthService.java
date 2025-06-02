package com.example.spring.service.AuthService;

import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {

    // 토큰 재발급
    MemberResponseDTO.LoginResultDTO refreshJwtToken(HttpServletRequest request);

    // 로그아웃
    void logout(HttpServletRequest request);
}
