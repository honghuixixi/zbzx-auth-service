package com.aek56.microservice.auth.weixin.menu;

/**
 * 子菜单项 :没有子菜单的菜单项，有可能是二级菜单项，也有可能是不含二级菜单的一级菜单
 * @author HongHui
 * @date   2017年12月1日
 */
public class MiniButton extends CommonButton {
	
	//小程序appid
	private String appid;
	//小程序跳转页面
    private String pagepath;
    
	public String getAppid() {
		return appid;
	}
	public void setAppid(String appid) {
		this.appid = appid;
	}
	public String getPagepath() {
		return pagepath;
	}
	public void setPagepath(String pagepath) {
		this.pagepath = pagepath;
	}
}
