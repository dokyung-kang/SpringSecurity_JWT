package com.example.spring.web.controller;

import com.example.spring.apiPayload.ApiResponse;
import com.example.spring.converter.MemberConverter;
import com.example.spring.domain.Member;
import com.example.spring.service.MemberService.MemberCommandService;
import com.example.spring.web.dto.MemberDTO.MemberRequestDTO;
import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Validated
@RequestMapping("/members")
public class MemberRestController {

    private final MemberCommandService memberCommandService;

    @PostMapping("/join")
    @Operation(summary = "유저 일반 회원가입 API",description = "일반 이메일로 회원가입하는 API입니다.")
    public ApiResponse<MemberResponseDTO.JoinResultDTO> join(@RequestBody @Valid MemberRequestDTO.JoinDto request){
        Member member = memberCommandService.joinMember(request);
        return ApiResponse.onSuccess(MemberConverter.toJoinResultDTO(member));
    }

    @PostMapping("/login")
    @Operation(summary = "유저 로그인 API",description = "이메일과 비밀번호로 일반 로그인하는 API입니다.")
    public ApiResponse<MemberResponseDTO.LoginResultDTO> login(@RequestBody @Valid MemberRequestDTO.LoginRequestDTO request) {
        return ApiResponse.onSuccess(memberCommandService.loginMember(request));
    }

}
