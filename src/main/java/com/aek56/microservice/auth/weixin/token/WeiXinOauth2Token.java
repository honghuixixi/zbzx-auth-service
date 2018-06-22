package com.aek56.microservice.auth.weixin.token;

import io.swagger.annotations.ApiModelProperty;

/**
 * 网页授权信息
 *	
 * @author HongHui
 * @date   2017年12月4日
 */
public class WeiXinOauth2Token {

	// 网页授权接口调用凭证
    private String accessToken;
    // 凭证有效时长
    private int expiresIn;
    // 用于刷新凭证
    private String refreshToken;
    // 用户标识
    private String openId;
    // 用户授权作用域
    private String scope;
    //只有在用户将公众号绑定到微信开放平台帐号后，才会出现该字段
  	private String unionId;
    
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	public int getExpiresIn() {
		return expiresIn;
	}
	public void setExpiresIn(int expiresIn) {
		this.expiresIn = expiresIn;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	public String getOpenId() {
		return openId;
	}
	public void setOpenId(String openId) {
		this.openId = openId;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public String getUnionId() {
		return unionId;
	}
	public void setUnionId(String unionId) {
		this.unionId = unionId;
	}
	@Override
	public String toString() {
		return "WeiXinOauth2Token [accessToken=" + accessToken + ", expiresIn=" + expiresIn + ", refreshToken="
				+ refreshToken + ", openId=" + openId + ", scope=" + scope + ", unionId=" + unionId + "]";
	}
	
}
