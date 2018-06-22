package com.aek56.microservice.auth.exception;

public class BusinessException extends RuntimeException{

	private static final long serialVersionUID = 1L;

	public static final String DEFAULT_FAULT_CODE = "0001";

	private String xCode;
	private String message;

	public BusinessException(String message){
		this(DEFAULT_FAULT_CODE, message);
	}

	public BusinessException(String xCode, String message) {
		this(xCode, message, null);
	}

	public BusinessException(String xCode, String message, Throwable throwable) {
		super("[" + xCode + "] - " + message, throwable);
		this.message = message;
		this.xCode = xCode;
	}

	public String getXCode() {
		return xCode;
	}

	public void setXCode(String xCode) {
		this.xCode = xCode;
	}

	public String getMessageWithoutCode(){
		return message;
	}

	@Override
	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

}