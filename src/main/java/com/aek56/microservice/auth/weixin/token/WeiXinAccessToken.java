package com.aek56.microservice.auth.weixin.token;

import java.util.Date;

/**
 * 微信token实体类 
 *	
 * @author HongHui
 * @date   2017年12月1日
 */
public class WeiXinAccessToken{

	//主键ID
	private Long id;
	
	//接入微信Token,接口访问凭证
	private String accessToken;
	
	//jsapi_ticket
	private String jsApiTicket;
	
	//凭证有效期,单位：秒
	private Long expiresIn;
	
	//获取Token时间
	private Date createTime;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public Long getExpiresIn() {
		return expiresIn;
	}

	public void setExpiresIn(Long expiresIn) {
		this.expiresIn = expiresIn;
	}

	public Date getCreateTime() {
		return createTime;
	}

	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}

	public String getJsApiTicket() {
		return jsApiTicket;
	}

	public void setJsApiTicket(String jsApiTicket) {
		this.jsApiTicket = jsApiTicket;
	}

	@Override
	public String toString() {
		return "WeiXinAccessToken [id=" + id + ", accessToken=" + accessToken + ", jsApiTicket=" + jsApiTicket
				+ ", expiresIn=" + expiresIn + ", createTime=" + createTime + "]";
	}
	
}
