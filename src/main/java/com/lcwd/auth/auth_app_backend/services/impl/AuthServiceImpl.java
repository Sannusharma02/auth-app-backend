package com.lcwd.auth.auth_app_backend.services.impl;

import com.lcwd.auth.auth_app_backend.dtos.UserDto;
import com.lcwd.auth.auth_app_backend.services.AuthService;
import com.lcwd.auth.auth_app_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;

    @Override
    public UserDto registerUser(UserDto userDto) {

        // logic
        // verify email
        // verify password
        //default role
        UserDto userDto1 = userService.createUser(userDto);
        return userDto1;

    }
}
