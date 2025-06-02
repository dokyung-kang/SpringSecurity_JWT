package com.example.spring.service.AuthService;

import com.example.spring.apiPayload.code.status.ErrorStatus;
import com.example.spring.apiPayload.exception.handler.MemberHandler;
import com.example.spring.config.security.jwt.JwtTokenProvider;
import com.example.spring.converter.MemberConverter;
import com.example.spring.domain.Member;
import com.example.spring.repository.MemberRepository.MemberRepository;
import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{

    private final JwtTokenProvider jwtTokenProvider;
    private final MemberRepository memberRepository;

    // 토큰 재발급
    @Override
    public MemberResponseDTO.LoginResultDTO refreshJwtToken(HttpServletRequest request) {

        String refreshToken = JwtTokenProvider.resolveToken(request);

        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new MemberHandler(ErrorStatus.INVALID_TOKEN);
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);
        String email = authentication.getName();

        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new MemberHandler(ErrorStatus.MEMBER_NOT_FOUND));

        if (!refreshToken.equals(member.getRefreshToken())) {
            throw new MemberHandler(ErrorStatus.INVALID_TOKEN);
        }

        Authentication newAuth = new UsernamePasswordAuthenticationToken(
                member.getEmail(), "", authentication.getAuthorities()
        );

        String newAccessToken = jwtTokenProvider.generateAccessToken(newAuth);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(newAuth);

        member.setRefreshToken(newRefreshToken);
        memberRepository.save(member);

        return MemberConverter.toLoginResultDTO(member.getId(), newAccessToken, newRefreshToken);
    }
}
