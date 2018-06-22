package com.aek56.microservice.auth.weixin.token;

/**
 * 网页授权信息
 *	
 * @author HongHui
 * @date   2017年12月4日
 */
public class WeiXinJsCode2Session {

	// 会话密钥
    private String session_key;
    // 用户在开放平台的唯一标识符。本字段在满足一定条件的情况下才返回。具体参看UnionID机制说明
    private String unionid;
    //用户唯一标识
    private String openId;
    
	public String getSession_key() {
		return session_key;
	}
	public void setSession_key(String session_key) {
		this.session_key = session_key;
	}
	public String getUnionid() {
		return unionid;
	}
	public void setUnionid(String unionid) {
		this.unionid = unionid;
	}
	public String getOpenId() {
		return openId;
	}
	public void setOpenId(String openId) {
		this.openId = openId;
	}
	@Override
	public String toString() {
		return "WeiXinJsCode2Session [session_key=" + session_key + ", unionid=" + unionid + ", openId=" + openId + "]";
	}
	
}
