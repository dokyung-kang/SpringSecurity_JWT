package com.example.spring.apiPayload.code.status;

import com.example.spring.apiPayload.code.BaseErrorCode;
import com.example.spring.apiPayload.code.ErrorReasonDTO;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorStatus implements BaseErrorCode {

    // 가장 일반적인 응답
    _INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "COMMON500", "서버 에러, 관리자에게 문의 바랍니다."),
    _BAD_REQUEST(HttpStatus.BAD_REQUEST,"COMMON400","잘못된 요청입니다."),
    _UNAUTHORIZED(HttpStatus.UNAUTHORIZED,"COMMON401","인증이 필요합니다."),
    _FORBIDDEN(HttpStatus.FORBIDDEN, "COMMON403", "금지된 요청입니다."),


    // 멤버 관려 에러
    MEMBER_NOT_FOUND(HttpStatus.BAD_REQUEST, "MEMBER4001", "사용자가 없습니다."),
    NICKNAME_NOT_EXIST(HttpStatus.BAD_REQUEST, "MEMBER4002", "닉네임은 필수 입니다."),
    INVALID_PASSWORD(HttpStatus.BAD_REQUEST, "MEMBER4003", "패스워드가 불일치합니다."),
    DUPLICATE_JOIN_REQUEST(HttpStatus.BAD_REQUEST, "MEMBER4004", "해당 이메일로 이미 가입된 사용자가 존재합니다."),
    INVALID_TOKEN(HttpStatus.BAD_REQUEST, "MEMBER4005", "유효하지 않은 토큰입니다."),
    
    // 카카오
    KAKAO_AUTH_FAIL(HttpStatus.UNAUTHORIZED, "KAKAO401", "카카오 인증 실패"),
    KAKAO_USERINFO_FAIL(HttpStatus.UNAUTHORIZED, "KAKAO402", "카카오 사용자 정보 요청 실패"),
    KAKAO_INVALID_CODE( HttpStatus.BAD_REQUEST,"KAKAO403", "유효하지 않거나 만료된 카카오 인증 코드입니다."),



    // 예시,,,
    ARTICLE_NOT_FOUND(HttpStatus.NOT_FOUND, "ARTICLE4001", "게시글이 없습니다."),

    // For test
    TEMP_EXCEPTION(HttpStatus.BAD_REQUEST, "TEMP4001", "이거는 테스트");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;

    @Override
    public ErrorReasonDTO getReason() {
        return ErrorReasonDTO.builder()
                .message(message)
                .code(code)
                .isSuccess(false)
                .build();
    }

    @Override
    public ErrorReasonDTO getReasonHttpStatus() {
        return ErrorReasonDTO.builder()
                .message(message)
                .code(code)
                .isSuccess(false)
                .httpStatus(httpStatus)
                .build()
                ;
    }
}