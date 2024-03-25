package com.iamneo.netflix.service;

import com.iamneo.netflix.dto.request.ForgotPasswordRequest;
import com.iamneo.netflix.dto.request.LoginRequest;
import com.iamneo.netflix.dto.request.RegisterRequest;
import com.iamneo.netflix.dto.response.BasicResponse;
import com.iamneo.netflix.dto.response.LoginResponse;

public interface AuthenticationService {

    BasicResponse<String> register(RegisterRequest registerRequest);

    BasicResponse<LoginResponse> login(LoginRequest loginRequest);

    BasicResponse<String> forgotPassword(ForgotPasswordRequest forgotPasswordRequest);

}
