package com.aek56.microservice.auth.weixin.menu;

/**
 * 整个菜单对象的封装
 * 
 * @author HongHui
 * @date 2017年12月1日
 */
public class Menu extends Button {

	private Button[] button;

	public Button[] getButton() {
		return button;
	}

	public void setButton(Button[] button) {
		this.button = button;
	}
}
