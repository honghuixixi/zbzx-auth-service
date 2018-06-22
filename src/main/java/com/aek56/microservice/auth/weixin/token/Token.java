package com.aek56.microservice.auth.weixin.token;

/**
 * 微信返回Token实体类
 *	
 * @author HongHui
 * @date   2017年12月1日
 */
public class Token {
	
	//接口访问凭证
	private String access_token;
	//凭证有效期(单位：秒)
	private Long expires_in;
	
	public String getAccess_token() {
		return access_token;
	}
	public void setAccess_token(String access_token) {
		this.access_token = access_token;
	}
	public Long getExpires_in() {
		return expires_in;
	}
	public void setExpires_in(Long expires_in) {
		this.expires_in = expires_in;
	}
	
	public String toString() {
		return "Token [access_token=" + access_token + ", expires_in=" + expires_in + "]";
	}
	
}
