package com.aek56.microservice.auth.weixin.menu;

/**
 * 菜单项的基类
 *	
 * @author HongHui
 * @date   2017年12月1日
 */
public class Button {

	private String name;  //所有一级菜单、二级菜单都共有一个相同的属性

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
}
