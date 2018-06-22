package com.aek56.microservice.auth.weixin.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 微信配置
 *	
 * @author HongHui
 * @date   2017年12月12日
 */
@Component
@ConfigurationProperties(prefix = "weixin")
public class WeiXinConfig {
	
	//微信公众号appId
	private String appId;
	//微信公众号appSecret
	private String appSecret;
	//获取ACCESS_TOKEN地址URL
	private String accessTokenUrl;
	//菜单创建URL
	private String createMenuUrl;
	//获取微信用户信息URL
	private String userInfoUrl;
	//获取sns用户信息URL
	private String snsUserInfoUrl;
	//获取网页授权凭证URL
	private String oauth2AccessTokenUrl;
	//开发者服务器使用登录凭证 code 获取 session_key 和 openid。
	private String jsCode2SessionUrl;
	//发送模板消息URL
	private String sendTemplateMsgUrl;
	//请求网页授权页面URL
	private String oauth2AuthorizeUrl;
	//获取jsapi_ticket
	private String jsApiGetTicketUrl;
	//下载微信服务器临时素材文件URL
	private String downloadWeiXinFileUrl;
	//ACCESS_TOKEN有效时间
	private int accessTokenEffectiveTime;
	//微信接入Token,用于验证微信接入
	private String token;
	//微信小程序APPID
	private String miniAppId;
	//微信小程序appSecret
	private String miniAppSecret;
	//点击微信维修消息，小程序跳转页面地址
	private String miniRepairPagePath;
	//点击服务平台消息，小程序跳转页面地址
	private String miniServicePagePath;
	//维修消息模板ID
	private String repairMessageTemplateId;
	//服务平台消息模板ID
	private String serviceMessageTemplateId;
	//账号绑定页面地址
	private String bandingPageUrl;
	//账号已绑定页面
	private String bandingSuccessPageUrl;
	//账号绑定异常页面
	private String bandingErrorPageUrl;
	//装备中心管理平台公众号登录页面
	private String bangdingLoginPageUrl;
	//微信公众号授权后的回调请求处理
	private String weixinCallBackUrl;
	
	public String getAppId() {
		return appId;
	}
	public void setAppId(String appId) {
		this.appId = appId;
	}
	public String getAppSecret() {
		return appSecret;
	}
	public void setAppSecret(String appSecret) {
		this.appSecret = appSecret;
	}
	public String getAccessTokenUrl() {
		return accessTokenUrl;
	}
	public void setAccessTokenUrl(String accessTokenUrl) {
		this.accessTokenUrl = accessTokenUrl;
	}
	public String getCreateMenuUrl() {
		return createMenuUrl;
	}
	public void setCreateMenuUrl(String createMenuUrl) {
		this.createMenuUrl = createMenuUrl;
	}
	public String getUserInfoUrl() {
		return userInfoUrl;
	}
	public void setUserInfoUrl(String userInfoUrl) {
		this.userInfoUrl = userInfoUrl;
	}
	public String getOauth2AccessTokenUrl() {
		return oauth2AccessTokenUrl;
	}
	public void setOauth2AccessTokenUrl(String oauth2AccessTokenUrl) {
		this.oauth2AccessTokenUrl = oauth2AccessTokenUrl;
	}
	public String getSendTemplateMsgUrl() {
		return sendTemplateMsgUrl;
	}
	public void setSendTemplateMsgUrl(String sendTemplateMsgUrl) {
		this.sendTemplateMsgUrl = sendTemplateMsgUrl;
	}
	public String getOauth2AuthorizeUrl() {
		return oauth2AuthorizeUrl;
	}
	public void setOauth2AuthorizeUrl(String oauth2AuthorizeUrl) {
		this.oauth2AuthorizeUrl = oauth2AuthorizeUrl;
	}
	public int getAccessTokenEffectiveTime() {
		return accessTokenEffectiveTime;
	}
	public void setAccessTokenEffectiveTime(int accessTokenEffectiveTime) {
		this.accessTokenEffectiveTime = accessTokenEffectiveTime;
	}
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
	public String getMiniAppId() {
		return miniAppId;
	}
	public void setMiniAppId(String miniAppId) {
		this.miniAppId = miniAppId;
	}
	public String getMiniRepairPagePath() {
		return miniRepairPagePath;
	}
	public void setMiniRepairPagePath(String miniRepairPagePath) {
		this.miniRepairPagePath = miniRepairPagePath;
	}
	public String getMiniServicePagePath() {
		return miniServicePagePath;
	}
	public void setMiniServicePagePath(String miniServicePagePath) {
		this.miniServicePagePath = miniServicePagePath;
	}
	public String getRepairMessageTemplateId() {
		return repairMessageTemplateId;
	}
	public void setRepairMessageTemplateId(String repairMessageTemplateId) {
		this.repairMessageTemplateId = repairMessageTemplateId;
	}
	public String getServiceMessageTemplateId() {
		return serviceMessageTemplateId;
	}
	public void setServiceMessageTemplateId(String serviceMessageTemplateId) {
		this.serviceMessageTemplateId = serviceMessageTemplateId;
	}
	public String getSnsUserInfoUrl() {
		return snsUserInfoUrl;
	}
	public void setSnsUserInfoUrl(String snsUserInfoUrl) {
		this.snsUserInfoUrl = snsUserInfoUrl;
	}
	public String getBandingPageUrl() {
		return bandingPageUrl;
	}
	public void setBandingPageUrl(String bandingPageUrl) {
		this.bandingPageUrl = bandingPageUrl;
	}
	public String getBandingSuccessPageUrl() {
		return bandingSuccessPageUrl;
	}
	public void setBandingSuccessPageUrl(String bandingSuccessPageUrl) {
		this.bandingSuccessPageUrl = bandingSuccessPageUrl;
	}
	public String getBandingErrorPageUrl() {
		return bandingErrorPageUrl;
	}
	public void setBandingErrorPageUrl(String bandingErrorPageUrl) {
		this.bandingErrorPageUrl = bandingErrorPageUrl;
	}
	public String getJsCode2SessionUrl() {
		return jsCode2SessionUrl;
	}
	public void setJsCode2SessionUrl(String jsCode2SessionUrl) {
		this.jsCode2SessionUrl = jsCode2SessionUrl;
	}
	public String getMiniAppSecret() {
		return miniAppSecret;
	}
	public void setMiniAppSecret(String miniAppSecret) {
		this.miniAppSecret = miniAppSecret;
	}
	public String getBangdingLoginPageUrl() {
		return bangdingLoginPageUrl;
	}
	public void setBangdingLoginPageUrl(String bangdingLoginPageUrl) {
		this.bangdingLoginPageUrl = bangdingLoginPageUrl;
	}
	public String getWeixinCallBackUrl() {
		return weixinCallBackUrl;
	}
	public void setWeixinCallBackUrl(String weixinCallBackUrl) {
		this.weixinCallBackUrl = weixinCallBackUrl;
	}
	public String getJsApiGetTicketUrl() {
		return jsApiGetTicketUrl;
	}
	public void setJsApiGetTicketUrl(String jsApiGetTicketUrl) {
		this.jsApiGetTicketUrl = jsApiGetTicketUrl;
	}
	public String getDownloadWeiXinFileUrl() {
		return downloadWeiXinFileUrl;
	}
	public void setDownloadWeiXinFileUrl(String downloadWeiXinFileUrl) {
		this.downloadWeiXinFileUrl = downloadWeiXinFileUrl;
	}
	@Override
	public String toString() {
		return "WeiXinConfig [appId=" + appId + ", appSecret=" + appSecret + ", accessTokenUrl=" + accessTokenUrl
				+ ", createMenuUrl=" + createMenuUrl + ", userInfoUrl=" + userInfoUrl + ", snsUserInfoUrl="
				+ snsUserInfoUrl + ", oauth2AccessTokenUrl=" + oauth2AccessTokenUrl + ", jsCode2SessionUrl="
				+ jsCode2SessionUrl + ", sendTemplateMsgUrl=" + sendTemplateMsgUrl + ", oauth2AuthorizeUrl="
				+ oauth2AuthorizeUrl + ", jsApiGetTicketUrl=" + jsApiGetTicketUrl + ", downloadWeiXinFileUrl="
				+ downloadWeiXinFileUrl + ", accessTokenEffectiveTime=" + accessTokenEffectiveTime + ", token=" + token
				+ ", miniAppId=" + miniAppId + ", miniAppSecret=" + miniAppSecret + ", miniRepairPagePath="
				+ miniRepairPagePath + ", miniServicePagePath=" + miniServicePagePath + ", repairMessageTemplateId="
				+ repairMessageTemplateId + ", serviceMessageTemplateId=" + serviceMessageTemplateId
				+ ", bandingPageUrl=" + bandingPageUrl + ", bandingSuccessPageUrl=" + bandingSuccessPageUrl
				+ ", bandingErrorPageUrl=" + bandingErrorPageUrl + ", bangdingLoginPageUrl=" + bangdingLoginPageUrl
				+ ", weixinCallBackUrl=" + weixinCallBackUrl + "]";
	}
}
