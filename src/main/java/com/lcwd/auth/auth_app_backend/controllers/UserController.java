package com.lcwd.auth.auth_app_backend.controllers;

import com.lcwd.auth.auth_app_backend.dtos.UserDto;
import com.lcwd.auth.auth_app_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@AllArgsConstructor
public class UserController {

    private final UserService userService;
    // create use api
    @PostMapping
    public ResponseEntity<UserDto> createUser(@RequestBody UserDto userDto){
        return  ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(userDto));
    }

    //get all user api
    @GetMapping
    public ResponseEntity<Iterable<UserDto>> getAllUsers()
    {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable("email") String email)
    {
        return ResponseEntity.ok(userService.getUserByEmail(email));
    }

    //delete User
    @DeleteMapping("/{userId}")
    public void deleteUser(@PathVariable("userId") String userId)
    {
        userService.deleteUser(userId);
    }

    //update user
    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(@RequestBody UserDto userDto, @PathVariable("userId") String userId) {
        return ResponseEntity.ok(userService.updateUser(userDto,userId));
    }

    //get user
    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUserById(@PathVariable("userId") String userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

}
