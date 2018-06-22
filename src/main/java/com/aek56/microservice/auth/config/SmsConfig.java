package com.aek56.microservice.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * 基础参数配置
 *
 */
@Configuration
@ConfigurationProperties("sms")
public class SmsConfig {

	private String usr;
	private String psw;
	private String authkey;
	private String url;
	private int loginTpl;
	private int codeTpl;
	private Integer expire;

	/**
	 * @return the usr
	 */
	public String getUsr() {
		return usr;
	}

	/**
	 * @param usr
	 *            the usr to set
	 */
	public void setUsr(String usr) {
		this.usr = usr;
	}

	/**
	 * @return the psw
	 */
	public String getPsw() {
		return psw;
	}

	/**
	 * @param psw
	 *            the psw to set
	 */
	public void setPsw(String psw) {
		this.psw = psw;
	}

	/**
	 * @return the authkey
	 */
	public String getAuthkey() {
		return authkey;
	}

	/**
	 * @param authkey
	 *            the authkey to set
	 */
	public void setAuthkey(String authkey) {
		this.authkey = authkey;
	}

	/**
	 * @return the url
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * @param url
	 *            the url to set
	 */
	public void setUrl(String url) {
		this.url = url;
	}

	/**
	 * @return the loginTpl
	 */
	public int getLoginTpl() {
		return loginTpl;
	}

	/**
	 * @param loginTpl
	 *            the loginTpl to set
	 */
	public void setLoginTpl(int loginTpl) {
		this.loginTpl = loginTpl;
	}

	/**
	 * @return the codeTpl
	 */
	public int getCodeTpl() {
		return codeTpl;
	}

	/**
	 * @param codeTpl
	 *            the codeTpl to set
	 */
	public void setCodeTpl(int codeTpl) {
		this.codeTpl = codeTpl;
	}

	public Integer getExpire() {
		return expire;
	}

	public void setExpire(Integer expire) {
		this.expire = expire;
	}

}
