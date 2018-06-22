package com.aek56.microservice.auth.weixin.message.template;

/**
 * 维修消息类型
 *	
 * @author HongHui
 * @date   2017年12月11日
 */
public enum WeiXinServiceMessageTypeEnum {
	
	NOTICE(0,"通知"),
	MESSAGE(1,"消息"),
	ARTICLE(2,"资料");
	
	private Integer type;
	private String name;
	
	private WeiXinServiceMessageTypeEnum(Integer type, String name) {
		this.type = type;
		this.name = name;
	}
	
	public Integer getType() {
		return type;
	}
	public void setType(Integer type) {
		this.type = type;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	
	
}
