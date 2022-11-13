package com.getarrays.userservice.exceptions;

import org.springframework.security.core.AuthenticationException;

public class CustomUsernameNotFoundException extends AuthenticationException {
    public CustomUsernameNotFoundException(String msg) {
        super(msg);
    }
}
