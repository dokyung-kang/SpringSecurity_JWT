package com.example.spring.service.OAuthService.naver;

import com.example.spring.apiPayload.code.status.ErrorStatus;
import com.example.spring.apiPayload.exception.handler.MemberHandler;
import com.example.spring.config.security.jwt.JwtTokenProvider;
import com.example.spring.converter.MemberConverter;
import com.example.spring.domain.Member;
import com.example.spring.domain.enums.Gender;
import com.example.spring.domain.enums.Role;
import com.example.spring.domain.enums.SocialType;
import com.example.spring.repository.MemberRepository.MemberRepository;
import com.example.spring.web.dto.MemberDTO.MemberResponseDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class NaverOAuthServiceImpl implements NaverOAuthService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RestTemplate restTemplate;

    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.naver.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.naver.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.provider.naver.token-uri}")
    private String naverTokenUrl;

    @Value("${spring.security.oauth2.client.provider.naver.user-info-uri}")
    private String naverUserInfoUrl;

    @Override
    @Transactional
    public MemberResponseDTO.LoginResultDTO naverLogin(String code) {
        String accessToken = getAccessTokenFromCode(code);
        Map<String, Object> userInfo = getUserInfoFromAccessToken(accessToken);

        Map<String, Object> response = (Map<String, Object>) userInfo.get("response");
        String email = (String) response.get("email");
        String name = (String) response.get("name");

        Member member = memberRepository.findByEmail(email)
                .orElseGet(() -> registerNaverMember(email, name));

        String jwtAccessToken = generateAccessToken(member);
        String jwtRefreshToken = generateRefreshToken(member);

        member.setRefreshToken(jwtRefreshToken);
        memberRepository.save(member);

        return MemberConverter.toLoginResultDTO(member.getId(), jwtAccessToken, jwtRefreshToken);
    }

    private String getAccessTokenFromCode(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("code", code);
        params.add("redirect_uri", redirectUri);

        try {
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                    naverTokenUrl, HttpMethod.POST, request, Map.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new MemberHandler(ErrorStatus.NAVER_AUTH_FAIL);
            }

            return Optional.ofNullable((String) response.getBody().get("access_token"))
                    .orElseThrow(() -> new MemberHandler(ErrorStatus.NAVER_AUTH_FAIL));

        } catch (Exception ex) {
            log.error("네이버 토큰 요청 중 에러 발생: {}", ex.getMessage());
            throw new MemberHandler(ErrorStatus.NAVER_AUTH_FAIL);
        }
    }

    private Map<String, Object> getUserInfoFromAccessToken(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<?> entity = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                naverUserInfoUrl, HttpMethod.GET, entity, Map.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new MemberHandler(ErrorStatus.NAVER_USERINFO_FAIL);
        }

        return response.getBody();
    }

    private Member registerNaverMember(String email, String name) {
        return memberRepository.save(
                Member.builder()
                        .email(email)
                        .name(name)
                        .password("OAUTH_" + UUID.randomUUID())
                        .gender(Gender.NONE)
                        .address("소셜로그인")
                        .specAddress("소셜로그인")
                        .role(Role.USER)
                        .socialType(SocialType.NAVER)
                        .build()
        );
    }

    private String generateAccessToken(Member member) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                member.getEmail(), null,
                Collections.singleton(() -> member.getRole().name())
        );
        return jwtTokenProvider.generateAccessToken(authentication);
    }

    private String generateRefreshToken(Member member) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                member.getEmail(), null,
                Collections.singleton(() -> member.getRole().name())
        );
        return jwtTokenProvider.generateRefreshToken(authentication);
    }
}
