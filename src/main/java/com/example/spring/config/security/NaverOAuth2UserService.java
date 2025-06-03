package com.example.spring.config.security;

import com.example.spring.domain.Member;
import com.example.spring.domain.enums.Gender;
import com.example.spring.domain.enums.Role;
import com.example.spring.domain.enums.SocialType;
import com.example.spring.repository.MemberRepository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class NaverOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        Map<String, Object> response = (Map<String, Object>) oAuth2User.getAttributes().get("response");

        String email = (String) response.get("email");
        String name = (String) response.get("name");

        if (email == null || name == null) {
            throw new OAuth2AuthenticationException("네이버 유저 정보(email 또는 name)가 없습니다.");
        }

        saveOrUpdateUser(email, name);

        Map<String, Object> modifiedAttributes = new HashMap<>(response);
        modifiedAttributes.put("email", email);

        return new DefaultOAuth2User(
                oAuth2User.getAuthorities(),
                modifiedAttributes,
                "email"
        );
    }

    private void saveOrUpdateUser(String email, String name) {
        if (memberRepository.findByEmail(email).isEmpty()) {
            Member newMember = Member.builder()
                    .email(email)
                    .name(name)
                    .password(passwordEncoder.encode("OAUTH_USER_" + UUID.randomUUID()))
                    .gender(Gender.NONE)
                    .address("소셜로그인")
                    .specAddress("소셜로그인")
                    .role(Role.USER)
                    .socialType(SocialType.NAVER)
                    .build();

            memberRepository.save(newMember);
        }
    }
}
