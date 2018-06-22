package com.aek56.microservice.auth.weixin.enums;

/**
 * 微信应用授权作用域
 *	
 * @author HongHui
 * @date   2017年12月5日
 */
public enum WeiXinScopeEnum {
	
	BASE("snsapi_base","不弹出授权页面，直接跳转，只能获取用户openid"),
	USERINFO("snsapi_userinfo","弹出授权页面，可通过openid拿到昵称、性别、所在地。并且，即使在未关注的情况下，只要用户授权，也能获取其信息");
	
	//作用域
	private String scope; 
	//描述
	private String desc;
	
	private WeiXinScopeEnum(String scope, String desc) {
		this.scope = scope;
		this.desc = desc;
	}
	
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public String getDesc() {
		return desc;
	}
	public void setDesc(String desc) {
		this.desc = desc;
	}
	
}
