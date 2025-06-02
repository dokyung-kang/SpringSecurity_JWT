package com.example.spring.service.MemberService;

import com.example.spring.apiPayload.code.status.ErrorStatus;
import com.example.spring.apiPayload.exception.handler.MemberHandler;
import com.example.spring.converter.MemberConverter;
import com.example.spring.domain.Member;
import com.example.spring.repository.MemberRepository.MemberRepository;
import com.example.spring.web.dto.MemberDTO.MemberRequestDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MemberCommandServiceImpl implements MemberCommandService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    // 일반 회원가입
    @Override
    @Transactional
    public Member joinMember(MemberRequestDTO.JoinDto request) {

        if(memberRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new MemberHandler(ErrorStatus.DUPLICATE_JOIN_REQUEST);
        }

        Member newMember = MemberConverter.toMember(request);
        newMember.encodePassword(passwordEncoder.encode(request.getPassword()));

        return memberRepository.save(newMember);
    }
}
