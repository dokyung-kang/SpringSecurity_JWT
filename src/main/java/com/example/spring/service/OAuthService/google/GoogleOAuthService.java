package com.example.spring.service.OAuthService.google;

import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;

public interface GoogleOAuthService {

    MemberResponseDTO.LoginResultDTO googleLogin(String code);
}
