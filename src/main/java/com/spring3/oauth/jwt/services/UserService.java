package com.spring3.oauth.jwt.services;

import com.spring3.oauth.jwt.dtos.UserInfoRequest;
import com.spring3.oauth.jwt.dtos.UserInfoResponse;


import java.util.List;


public interface UserService {

    UserInfoResponse saveUser(UserInfoRequest userInfoRequest);

    UserInfoResponse getUser();

    List<UserInfoResponse> getAllUser();


}
