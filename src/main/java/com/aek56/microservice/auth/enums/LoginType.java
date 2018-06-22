package com.aek56.microservice.auth.enums;

/**
 *  登录类型
 *	
 * @author HongHui
 * @date   2017年8月2日
 */
public enum LoginType {

	VALIDATE_CODE_LOGIN("短信验证码登录",1);
	
	private String title;

	private Integer number;

	private LoginType(String title, Integer number) {
		this.title = title;
		this.setNumber(number);
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public Integer getNumber() {
		return number;
	}

	public void setNumber(Integer number) {
		this.number = number;
	}

}
