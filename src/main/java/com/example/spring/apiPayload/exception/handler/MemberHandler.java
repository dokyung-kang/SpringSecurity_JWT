package com.example.spring.apiPayload.exception.handler;

import com.example.spring.apiPayload.code.BaseErrorCode;
import com.example.spring.apiPayload.exception.GeneralException;

public class MemberHandler extends GeneralException {
    public MemberHandler(BaseErrorCode errorCode) {
        super(errorCode);
    }
}