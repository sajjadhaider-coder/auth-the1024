package com.spring3.oauth.jwt.controllers;

import com.spring3.oauth.jwt.dtos.*;
import com.spring3.oauth.jwt.exceptions.InvalidCredentialsException;
import com.spring3.oauth.jwt.exceptions.UserNotFoundException;
import com.spring3.oauth.jwt.models.RefreshToken;
import com.spring3.oauth.jwt.services.JwtService;
import com.spring3.oauth.jwt.services.RefreshTokenService;
import com.spring3.oauth.jwt.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class UserController {

    @Autowired
    private UserService userService;  // Inject UserService | 注入UserService

    @Autowired
    private JwtService jwtService;  // Inject JwtService for token generation | 注入JwtService用于生成令牌

    @Autowired
    private RefreshTokenService refreshTokenService;  // Inject RefreshTokenService for token management | 注入RefreshTokenService用于管理刷新令牌

    @Autowired
    private AuthenticationManager authenticationManager;  // Inject AuthenticationManager for user authentication | 注入AuthenticationManager用于用户认证

    // Register a new user | 注册新用户
    @PostMapping(value = "/signup")
    public ResponseEntity<UserInfoResponse> saveUser(@RequestBody UserInfoRequest userRequest) {
        try {
            UserInfoResponse userResponse = userService.saveUser(userRequest);
            return new ResponseEntity<>(userResponse, HttpStatus.CREATED);  // 201 Created for successful user creation | 201 表示成功创建用户
        } catch (Exception e) {
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);  // 500 Internal Server Error for any unexpected exceptions | 500 表示服务器内部错误
        }
    }

    // Get the list of all users | 获取所有用户列表
    @GetMapping("/users")
    public ResponseEntity<List<UserInfoResponse>> getAllUsers() {
        List<UserInfoResponse> userResponses = userService.getAllUser();
        if (userResponses.isEmpty()) {
            throw new UserNotFoundException("No users found.");  // Custom exception when no users are found | 没有找到用户时抛出自定义异常
        }
        return new ResponseEntity<>(userResponses, HttpStatus.OK);  // 200 OK for successful response | 200 表示成功响应
    }

    // Get profile information of the current user (Requires ROLE_ADMIN) | 获取当前用户的资料信息（需要ROLE_ADMIN权限）
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping("/profile")
    public ResponseEntity<UserInfoResponse> getUserProfile() {
        UserInfoResponse userResponse = userService.getUser();
        if (userResponse == null) {
            throw new UserNotFoundException("User not found.");  // Custom exception for user not found | 找不到用户时抛出自定义异常
        }
        return new ResponseEntity<>(userResponse, HttpStatus.OK);  // 200 OK for successful profile retrieval | 200 表示成功获取用户资料
    }

    // Example endpoint to return a welcome message (Requires ROLE_ADMIN) | 示例端点返回欢迎信息（需要ROLE_ADMIN权限）
    @Operation(summary = "Get greeting message", description = "Returns a greeting message")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return new ResponseEntity<>("Welcome", HttpStatus.OK);  // 200 OK for a successful request | 200 表示请求成功
    }

    // Authenticate user and generate JWT access token | 认证用户并生成JWT访问令牌
    @PostMapping("/login")
    public ResponseEntity<JwtResponseDTO> authenticateAndGetToken(@RequestBody AuthRequestDTO authRequestDTO) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequestDTO.getAccountNumber(), authRequestDTO.getPassword())  // Authenticate using account number and password | 使用账号和密码进行认证
        );

        if (authentication.isAuthenticated()) {
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(authRequestDTO.getAccountNumber());  // Create refresh token for the authenticated user | 为已认证用户创建刷新令牌
            JwtResponseDTO jwtResponse = JwtResponseDTO.builder()
                    .accessToken(jwtService.GenerateToken(authRequestDTO.getAccountNumber()))  // Generate access token | 生成访问令牌
                    .token(refreshToken.getToken()).build();  // Include refresh token in the response | 在响应中包含刷新令牌
            return new ResponseEntity<>(jwtResponse, HttpStatus.OK);  // 200 OK for successful authentication | 200 表示成功认证
        } else {
            throw new InvalidCredentialsException("Invalid credentials provided.");  // Custom exception for invalid login credentials | 提供无效登录凭据时抛出自定义异常
        }
    }

    // Refresh the access token using the refresh token | 使用刷新令牌刷新访问令牌
    @PostMapping("/refreshToken")
    public ResponseEntity<JwtResponseDTO> refreshToken(@RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO) {
        JwtResponseDTO jwtResponse = refreshTokenService.findByToken(refreshTokenRequestDTO.getToken())
                .map(refreshTokenService::verifyExpiration)  // Verify the refresh token expiration | 验证刷新令牌是否过期
                .map(RefreshToken::getUserInfo)
                .map(userInfo -> {
                    String accessToken = jwtService.GenerateToken(userInfo.getUsername());  // Generate new access token for the user | 为用户生成新的访问令牌
                    return JwtResponseDTO.builder()
                            .accessToken(accessToken)
                            .token(refreshTokenRequestDTO.getToken()).build();  // Return the same refresh token with the new access token | 返回相同的刷新令牌和新的访问令牌
                }).orElseThrow(() -> new RuntimeException("Refresh Token is not in DB."));  // Throw exception if refresh token is not found | 未找到刷新令牌时抛出异常

        return new ResponseEntity<>(jwtResponse, HttpStatus.OK);  // 200 OK for successful token refresh | 200 表示成功刷新令牌
    }
}
