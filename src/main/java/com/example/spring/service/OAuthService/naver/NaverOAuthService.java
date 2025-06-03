package com.example.spring.service.OAuthService.naver;

import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;

public interface NaverOAuthService {

    MemberResponseDTO.LoginResultDTO naverLogin(String code);
}
