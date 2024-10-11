package com.spring3.oauth.jwt.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.HashSet;
import java.util.Set;

@Entity
@Data
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "USERS")
public class UserInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID")
    private long id;

    @NotNull
    @Size(min = 3, max = 50)
    @Column(name = "NICKNAME", nullable = false)
    private String nickname;

    @NotNull
    @Column(name = "ACCOUNT_NUMBER", unique = true, nullable = false, length = 20)
    @JsonIgnore // Hide sensitive data if necessary
    private String username;

    @NotNull
    @Column(name = "VERIFICATION_CODE", length = 10)
    private String verificationCode;

    @NotNull
    @JsonIgnore // Prevent password from being serialized
    @Column(name = "PASSWORD", nullable = false)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.MERGE, CascadeType.PERSIST})
    @JoinTable(
            name = "USER_ROLES",
            joinColumns = @JoinColumn(name = "USER_ID"),
            inverseJoinColumns = @JoinColumn(name = "ROLE_ID")
    )
    private Set<UserRole> roles = new HashSet<>();

}
