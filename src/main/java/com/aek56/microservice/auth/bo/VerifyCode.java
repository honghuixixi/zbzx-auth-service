package com.aek56.microservice.auth.bo;

import java.util.Date;

/**
 * 记录短信发送验证码类
 *	
 * @author HongHui
 * @date   2017年8月1日
 */
public class VerifyCode {

	private String code;// 验证码

	private Date sendTime;// 发送时间

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public Date getSendTime() {
		return sendTime;
	}

	public void setSendTime(Date sendTime) {
		this.sendTime = sendTime;
	}

}
