package com.example.spring.web.controller;

import com.example.spring.apiPayload.ApiResponse;
import com.example.spring.service.OAuthService.kakao.KakaoOAuthService;
import com.example.spring.service.OAuthService.naver.NaverOAuthService;
import com.example.spring.web.dto.MemberDTO.MemberRequestDTO;
import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/oauth")
public class OAuthController {

    private final KakaoOAuthService kakaoOAuthService;
    private final NaverOAuthService naverOAuthService;

    @PostMapping("/kakao")
    @Operation(
            summary = "카카오 로그인 API",
            description = "프론트에서 받은 인가코드(code)를 통해 카카오 로그인을 수행하고 JWT 토큰을 반환합니다."
    )
    public ApiResponse<MemberResponseDTO.LoginResultDTO> kakaoLogin(@RequestBody @Valid MemberRequestDTO.OAuthCodeRequestDTO request) {
        String code = request.getCode();
        MemberResponseDTO.LoginResultDTO result = kakaoOAuthService.kakaoLogin(code);
        return ApiResponse.onSuccess(result);
    }

    @PostMapping("/naver")
    @Operation(
            summary = "네이버 로그인 API",
            description = "프론트에서 받은 인가코드(code)를 통해 네이버 로그인을 수행하고 JWT 토큰을 반환합니다."
    )
    public ApiResponse<MemberResponseDTO.LoginResultDTO> naverLogin(@RequestBody @Valid MemberRequestDTO.OAuthCodeRequestDTO request) {
        String code = request.getCode();
        MemberResponseDTO.LoginResultDTO result = naverOAuthService.naverLogin(code);
        return ApiResponse.onSuccess(result);
    }
}