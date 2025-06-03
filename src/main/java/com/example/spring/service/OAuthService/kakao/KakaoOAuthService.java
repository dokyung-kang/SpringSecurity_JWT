package com.example.spring.service.OAuthService.kakao;

import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;

public interface KakaoOAuthService {

    MemberResponseDTO.LoginResultDTO kakaoLogin(String code);
}
