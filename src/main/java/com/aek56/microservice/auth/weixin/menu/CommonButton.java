package com.aek56.microservice.auth.weixin.menu;

/**
 * 子菜单项 :没有子菜单的菜单项，有可能是二级菜单项，也有可能是不含二级菜单的一级菜单
 * @author HongHui
 * @date   2017年12月1日
 */
public class CommonButton extends Button {
	
	//菜单的响应动作类型，view表示网页类型，click表示点击类型，miniprogram表示小程序类型
	private String type;
	//菜单KEY值，用于消息接口推送，不超过128字节
    private String key;
    //网页链接
    private String url;
    
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public String getUrl() {
		return url;
	}
	public void setUrl(String url) {
		this.url = url;
	}
}
