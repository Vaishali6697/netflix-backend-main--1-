package com.iamneo.netflix.service.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.iamneo.netflix.dto.request.ForgotPasswordRequest;
import com.iamneo.netflix.dto.request.LoginRequest;
import com.iamneo.netflix.dto.request.RegisterRequest;
import com.iamneo.netflix.dto.response.BasicResponse;
import com.iamneo.netflix.dto.response.LoginResponse;
import com.iamneo.netflix.model.Token;
import com.iamneo.netflix.model.User;
import com.iamneo.netflix.repository.TokenRepository;
import com.iamneo.netflix.repository.UserRepository;
import com.iamneo.netflix.service.AuthenticationService;
import com.iamneo.netflix.utils.JwtUtils;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@SuppressWarnings("null")
public class AuthenticationServiceImpl implements AuthenticationService{

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    @Override
    public BasicResponse<String> register(RegisterRequest registerRequest) {
        Optional<User> isUserExists = userRepository.findByEmail(registerRequest.getEmail());
        if (isUserExists.isPresent()) {
            return BasicResponse.<String>builder().message("User already exists with email id " + registerRequest.getEmail()).data("").build();
        }

        var user = User.builder()
                .name(registerRequest.getName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword())).build();
        userRepository.save(user);
        return BasicResponse.<String>builder().message("User registered successfully").data("").build();
    }

    @Override
    public BasicResponse<LoginResponse> login(LoginRequest loginRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        var user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole().toString());
        var accessToken = jwtUtils.generateToken(claims, user);
        revokeAllUserToken(user);
        saveUserToken(accessToken, user);
        return BasicResponse.<LoginResponse>builder()
                .message("User logged in successfully.")
                .data(LoginResponse.builder().accessToken(accessToken).build())
                .build();
    }

    private void saveUserToken(String accessToken, User user) {
        var token = Token.builder().token(accessToken).user(user).expired(false).revoked(false).build();
        tokenRepository.save(token);
    }

    private void revokeAllUserToken(User user) {
        var validUserTokens = tokenRepository.findAllByUser_IdAndRevokedFalseAndExpiredFalse(user.getId());
        if (validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    @Override
    public BasicResponse<String> forgotPassword(ForgotPasswordRequest forgotPasswordRequest) {
        var user = userRepository.findByEmail(forgotPasswordRequest.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (!passwordEncoder.matches( forgotPasswordRequest.getCurrentPAssword(), user.getPassword())) {
            return BasicResponse.<String>builder().message("Wrong password").data("").build();
        }
        if(!forgotPasswordRequest.getNewPassword().equals(forgotPasswordRequest.getConfirmPassword())){
            return BasicResponse.<String>builder().message("Password mismatch").data("").build();
        }
        user.setPassword(passwordEncoder.encode(forgotPasswordRequest.getNewPassword()));
        userRepository.save(user);
        return BasicResponse.<String>builder().message("Password updated successfully.").data("").build();
    }

}
