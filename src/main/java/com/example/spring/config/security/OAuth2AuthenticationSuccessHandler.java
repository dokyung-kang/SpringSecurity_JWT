package com.example.spring.config.security;

import com.example.spring.apiPayload.code.status.ErrorStatus;
import com.example.spring.apiPayload.exception.handler.MemberHandler;
import com.example.spring.config.security.jwt.JwtTokenProvider;
import com.example.spring.domain.Member;
import com.example.spring.repository.MemberRepository.MemberRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final MemberRepository memberRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        String email = ((DefaultOAuth2User) authentication.getPrincipal()).getAttribute("email");
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new MemberHandler(ErrorStatus.MEMBER_NOT_FOUND));

        String accessToken = jwtTokenProvider.generateAccessToken(authentication);
        String refreshToken = jwtTokenProvider.generateRefreshToken(authentication);

        member.setRefreshToken(refreshToken);
        memberRepository.save(member);

        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"accessToken\":\"" + accessToken + "\",\"refreshToken\":\"" + refreshToken + "\"}");
        response.getWriter().flush();
    }
}

