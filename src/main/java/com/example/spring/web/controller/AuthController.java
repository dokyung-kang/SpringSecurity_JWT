package com.example.spring.web.controller;

import com.example.spring.apiPayload.ApiResponse;
import com.example.spring.service.AuthService.AuthService;
import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/token/refresh")
    @Operation(summary = "새로운 토큰 재발급 API",
            description = "refreshToken을 헤더에 넣어 새로운 토큰을 재발급받는 API입니다.",
            security = { @SecurityRequirement(name = "JWT TOKEN") }
    )
    public ApiResponse<MemberResponseDTO.LoginResultDTO> reissueToken(HttpServletRequest request) {
        MemberResponseDTO.LoginResultDTO result = authService.refreshJwtToken(request);
        return ApiResponse.onSuccess(result);
    }
}