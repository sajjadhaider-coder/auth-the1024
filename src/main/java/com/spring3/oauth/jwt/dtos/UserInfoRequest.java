package com.spring3.oauth.jwt.dtos;

import com.spring3.oauth.jwt.models.UserRole;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class UserInfoRequest {

    @NotNull
    @Size(min = 3, max = 50)
    private String nickname;

    private Long id;

    @NotNull
    @Size(min = 8, message = "Password must be at least 8 characters long")
    private String password;

    @NotNull
    @Size(min = 8, message = "Confirm password must be at least 8 characters long")
    private String confirmPassword;

    @NotNull
    @Size(min = 10, max = 20, message = "Account number must be between 10 and 20 characters")
    private String accountNumber;

    @NotNull
    @Size(min = 6, max = 10, message = "Verification code must be between 6 and 10 characters")
    private String verificationCode;

    @NotNull
    private Set<@Valid UserRole> roles;

     public Long getId() {
        return id;
    }

}
