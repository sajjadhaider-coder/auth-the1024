package com.spring3.oauth.jwt.services;

import com.spring3.oauth.jwt.dtos.UserInfoRequest;
import com.spring3.oauth.jwt.dtos.UserInfoResponse;
import com.spring3.oauth.jwt.models.UserInfo;
import com.spring3.oauth.jwt.repositories.UserRepository;
import org.modelmapper.ModelMapper;
import org.modelmapper.TypeToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.lang.reflect.Type;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class UserServiceImpl implements com.spring3.oauth.jwt.services.UserService {

    @Autowired
    UserRepository userRepository;

    ModelMapper modelMapper = new ModelMapper();



    @Override
    public UserInfoResponse saveUser(UserInfoRequest userInfoRequest) {
        if(userInfoRequest.getAccountNumber()== null){
            throw new RuntimeException("Parameter account number is not found in request..!!");
        } else if(userInfoRequest.getPassword() == null){
            throw new RuntimeException("Parameter password is not found in request..!!");
        }


//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        UserDetails userDetail = (UserDetails) authentication.getPrincipal();
//        String usernameFromAccessToken = userDetail.getUsername();
//
//        UserInfo currentUser = userRepository.findByUsername(usernameFromAccessToken);

        UserInfo savedUser = null;

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String rawPassword = userInfoRequest.getPassword();
        String encodedPassword = encoder.encode(rawPassword);

        UserInfo user = modelMapper.map(userInfoRequest, UserInfo.class);
        user.setUsername(userInfoRequest.getAccountNumber());
        user.setPassword(encodedPassword);
        if(userInfoRequest.getId() != null && userInfoRequest.getId() > 0){
            UserInfo oldUser = userRepository.findFirstById(userInfoRequest.getId());
            if(oldUser != null){
                oldUser.setId(user.getId());
                oldUser.setPassword(user.getPassword());
                oldUser.setNickname(user.getNickname());
                oldUser.setUsername(user.getUsername());
                oldUser.setVerificationCode(user.getVerificationCode());
                oldUser.setRoles(user.getRoles());

                savedUser = userRepository.save(oldUser);
                userRepository.refresh(savedUser);
            } else {
                throw new RuntimeException("Can't find record with identifier: " + userInfoRequest.getId());
            }
        } else {
//            user.setCreatedBy(currentUser);
            savedUser = userRepository.save(user);
        }
        userRepository.refresh(savedUser);
        UserInfoResponse userResponse = modelMapper.map(savedUser, UserInfoResponse.class);

        if (savedUser.getUsername() != null )
            userResponse.setAccountNumber(user.getUsername());

        return userResponse;
    }

    @Override
    public UserInfoResponse getUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetail = (UserDetails) authentication.getPrincipal();
        String usernameFromAccessToken = userDetail.getUsername();
        UserInfo user = userRepository.findByUsername(usernameFromAccessToken);
        UserInfoResponse userResponse = modelMapper.map(user, UserInfoResponse.class);

        if (user.getUsername() != null )
            userResponse.setAccountNumber(user.getUsername());

        return userResponse;
    }

    @Override
    public List<UserInfoResponse> getAllUser() {
        List<UserInfo> users = (List<UserInfo>) userRepository.findAll();
        Type setOfDTOsType = new TypeToken<List<UserInfoResponse>>(){}.getType();
        List<UserInfoResponse> userResponses = modelMapper.map(users, setOfDTOsType);
        for (int i = 0; i < users.size(); i++) {
            userResponses.get(i).setAccountNumber(users.get(i).getUsername());
        }

        return userResponses;
    }
}
