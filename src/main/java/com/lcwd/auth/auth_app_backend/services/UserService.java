package com.lcwd.auth.auth_app_backend.services;

import com.lcwd.auth.auth_app_backend.dtos.UserDto;

public interface UserService {

    // Create User
    UserDto createUser(UserDto userDto);

    //get user by email
    UserDto getUserByEmail(String email);

    //Update User
    UserDto updateUser(UserDto userDto, String userId);

    //delete user
    void deleteUser(String userId);

    //get user by id
    UserDto getUserById(String userId);

    //get all users
    Iterable<UserDto> getAllUsers();
}
