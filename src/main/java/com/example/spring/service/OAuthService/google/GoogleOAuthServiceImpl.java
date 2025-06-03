package com.example.spring.service.OAuthService.google;

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
public class GoogleOAuthServiceImpl implements GoogleOAuthService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RestTemplate restTemplate;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.provider.google.token-uri}")
    private String googleTokenUri;

    @Value("${spring.security.oauth2.client.provider.google.user-info-uri}")
    private String googleUserInfoUri;

    @Override
    @Transactional
    public MemberResponseDTO.LoginResultDTO googleLogin(String code) {
        String accessToken = getAccessTokenFromCode(code);
        Map<String, Object> userInfo = getUserInfoFromAccessToken(accessToken);

        String email = (String) userInfo.get("email");
        String name = (String) userInfo.get("name");

        Member member = memberRepository.findByEmail(email)
                .orElseGet(() -> registerGoogleMember(email, name));

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
        params.add("redirect_uri", redirectUri);
        params.add("code", code);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    googleTokenUri, HttpMethod.POST, request, Map.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new MemberHandler(ErrorStatus.GOOGLE_AUTH_FAIL);
            }

            return Optional.ofNullable((String) response.getBody().get("access_token"))
                    .orElseThrow(() -> new MemberHandler(ErrorStatus.GOOGLE_AUTH_FAIL));
        } catch (Exception e) {
            throw new MemberHandler(ErrorStatus.GOOGLE_AUTH_FAIL);
        }
    }

    private Map<String, Object> getUserInfoFromAccessToken(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<?> entity = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                googleUserInfoUri, HttpMethod.GET, entity, Map.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new MemberHandler(ErrorStatus.GOOGLE_USERINFO_FAIL);
        }

        return response.getBody();
    }

    private Member registerGoogleMember(String email, String name) {
        return memberRepository.save(
                Member.builder()
                        .email(email)
                        .name(name)
                        .password("OAUTH_" + UUID.randomUUID())
                        .gender(Gender.NONE)
                        .address("소셜로그인")
                        .specAddress("소셜로그인")
                        .role(Role.USER)
                        .socialType(SocialType.GOOGLE)
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
