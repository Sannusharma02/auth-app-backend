package com.lcwd.auth.auth_app_backend.exceptions;

import com.lcwd.auth.auth_app_backend.dtos.ApiError;
import com.lcwd.auth.auth_app_backend.dtos.ErrorResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.security.auth.login.CredentialExpiredException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler({
            UsernameNotFoundException.class,
            BadCredentialsException.class,
            CredentialExpiredException.class,
            DisabledException.class,
            ExpiredJwtException.class,
            JwtException.class,
            AuthenticationException.class,
    })
    public ResponseEntity<ApiError> handleAuthException(Exception e, HttpServletRequest request){
        logger.info("Exception : {}",e.getClass().getName());
        var apiError = ApiError.of(HttpStatus.BAD_REQUEST.value(),"Bad Request",e.getMessage(),request.getRequestURI());
        return ResponseEntity.badRequest().body(apiError);
    }

    //resource no found exception handler :: method
    @ExceptionHandler(value = { ResourceNotFoundException.class })
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException exception){
        ErrorResponse internalServerError = new ErrorResponse(exception.getMessage(), HttpStatus.NOT_FOUND,404);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(internalServerError);
    }

    //resource no found exception handler ::
    @ExceptionHandler(value = { IllegalArgumentException.class })
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException exception){
        ErrorResponse internalServerError = new ErrorResponse(exception.getMessage(), HttpStatus.BAD_REQUEST,400);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(internalServerError);
    }


}
