package com.aek56.microservice.auth.exception;

/**
 * 用户未存在
 *
 * @author zj@aek56.com
 */
public class UserNotExistException extends RuntimeException {

	private static final long serialVersionUID = -1245233896575348574L;

	public UserNotExistException(String message) {
        super(message);
    }

    public UserNotExistException(String message, Throwable cause) {
        super(message, cause);
    }
}
