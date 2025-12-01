package com.lcwd.auth.auth_app_backend.services.impl;

import com.lcwd.auth.auth_app_backend.dtos.UserDto;
import com.lcwd.auth.auth_app_backend.entities.User;
import com.lcwd.auth.auth_app_backend.enums.Provider;
import com.lcwd.auth.auth_app_backend.exceptions.ResourceNotFoundException;
import com.lcwd.auth.auth_app_backend.helpers.UserHelper;
import com.lcwd.auth.auth_app_backend.repositories.UserRepository;
import com.lcwd.auth.auth_app_backend.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {

        if(userDto.getEmail()==null || userDto.getEmail().isBlank()){
            throw new IllegalArgumentException("Email is required");
        }

        if(userRepository.existsByEmail(userDto.getEmail())){
            throw new IllegalArgumentException("USer with given email already exists");
        }

        User user = modelMapper.map(userDto,User.class);
        user.setProvider(userDto.getProvider()!=null ? userDto.getProvider() : Provider.LOCAL);
        //role assign here to user __ for auth
        // todo
        User savedUser = userRepository.save(user);

        return modelMapper.map(savedUser,UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {
        User user = userRepository
                .findByEmail(email)
                .orElseThrow(()-> new ResourceNotFoundException("User not found with given email id"));

        return modelMapper.map(user,UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uid = UserHelper.parseUUID(userId);
        User exsitingUser = userRepository
                .findById(uid)
                .orElseThrow(()-> new ResourceNotFoundException("User not found with given id"));
        // we are not going to change email id for this project
        if(userDto.getName()!=null) exsitingUser.setName(userDto.getName());
        if(userDto.getImage()!=null) exsitingUser.setImage(userDto.getImage());
        if(userDto.getProvider()!=null) exsitingUser.setProvider(userDto.getProvider());
        //TODO: Change password updation logic...
        if(userDto.getPassword()!=null) exsitingUser.setPassword(userDto.getPassword());
        exsitingUser.setEnable(userDto.isEnable());
        userRepository.save(exsitingUser);
        exsitingUser.setUpdatedAt(Instant.now());
        return modelMapper.map(exsitingUser,UserDto.class);
    }

    @Override
    public void deleteUser(String userId) {
        UUID uId = UUID.fromString(userId);
        userRepository.findById(uId).orElseThrow(()-> new ResourceNotFoundException("User not found with given user id"));
        userRepository.deleteById(uId);
    }

    @Override
    public UserDto getUserById(String userId) {
        User user = userRepository.findById(UserHelper.parseUUID(userId)).orElseThrow(()-> new ResourceNotFoundException("User not found with given user id"));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepository
                .findAll().stream()
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
    }
}
