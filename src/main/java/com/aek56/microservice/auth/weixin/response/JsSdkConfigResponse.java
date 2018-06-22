package com.aek56.microservice.auth.weixin.response;

/**
 *  JsSDK配置返回信息
 *
 * @author  Honghui
 * @date    2018年3月1日
 * @version 1.0
 */
public class JsSdkConfigResponse {

	//公众号唯一标识
	private String appId;
	//生成签名的时间戳
	private String timestamp;
	//生成签名的随机串
	private String nonceStr;
	//签名
	private String signature;
	
	public JsSdkConfigResponse(String appId, String timestamp, String nonceStr, String signature) {
		this.appId = appId;
		this.timestamp = timestamp;
		this.nonceStr = nonceStr;
		this.signature = signature;
	}
	
	public String getAppId() {
		return appId;
	}
	public void setAppId(String appId) {
		this.appId = appId;
	}
	public String getTimestamp() {
		return timestamp;
	}
	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}
	public String getNonceStr() {
		return nonceStr;
	}
	public void setNonceStr(String nonceStr) {
		this.nonceStr = nonceStr;
	}
	public String getSignature() {
		return signature;
	}
	public void setSignature(String signature) {
		this.signature = signature;
	}
	@Override
	public String toString() {
		return "JsSdkConfigResponse [appId=" + appId + ", timestamp=" + timestamp + ", nonceStr=" + nonceStr
				+ ", signature=" + signature + "]";
	}
}
