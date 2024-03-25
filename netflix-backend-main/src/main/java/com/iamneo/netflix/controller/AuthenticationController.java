package com.iamneo.netflix.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.service.annotation.PatchExchange;

import com.iamneo.netflix.dto.request.ForgotPasswordRequest;
import com.iamneo.netflix.dto.request.LoginRequest;
import com.iamneo.netflix.dto.request.RegisterRequest;
import com.iamneo.netflix.dto.response.BasicResponse;
import com.iamneo.netflix.dto.response.LoginResponse;
import com.iamneo.netflix.service.AuthenticationService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/netflix/api/v1/authentication")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "It's used to authenticate and authorize the user.")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    @Operation(summary = "User registration", description = "For the registration process, I collect user credentials such as name, email, and password.")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest){
        BasicResponse<String> response =  new BasicResponse<>();
        try {
            response = authenticationService.register(registerRequest);
            return new ResponseEntity<>(response, HttpStatus.ACCEPTED);
        } catch (Exception e) {
            response.setMessage("Something went wrong.");
            response.setData("");
            return new ResponseEntity<>(response, HttpStatus.EXPECTATION_FAILED);
        }

    }

    @PostMapping("/login")
    @Operation(summary = "User authentication", description = "Upon successful authentication using user credentials (email and password), a JSON Web Token (JWT) is generated.")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest){
        BasicResponse<LoginResponse> response = new BasicResponse<>();
        try {
            response = authenticationService.login(loginRequest);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            response.setMessage("Something went wrong.");
            response.setData(LoginResponse.builder().accessToken("").build());
            return new ResponseEntity<>(response, HttpStatus.EXPECTATION_FAILED);
        }
    }

    @PatchExchange("/forgot-password")
    @Operation(summary = "Reset user password", description = "For the \"forgot password\" feature, I will collect the user's email, their current password (to verify against the stored password in the database), and the new password along with a confirmation password to reset the user's password.")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest forgotPasswordRequest){
        BasicResponse<String> response = new BasicResponse<>();
        try {
            response = authenticationService.forgotPassword(forgotPasswordRequest);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            response.setMessage("Something went wrong.");
            response.setData("");
            return new ResponseEntity<>(response, HttpStatus.EXPECTATION_FAILED);
        }
    }
}
