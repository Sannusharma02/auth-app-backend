package com.lcwd.auth.auth_app_backend.exceptions;

public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }
    public ResourceNotFoundException(){
        super("Resourse not found");
    }
}
