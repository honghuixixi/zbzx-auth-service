package com.aek56.microservice.auth.weixin.message.template;

/**
 * 维修消息类型
 *	
 * @author HongHui
 * @date   2017年12月11日
 */
public enum WeiXinRepairMessageTypeEnum {
	
	TAKE_ORDER(1,"接单","REP_APPLY_TAKE_NEW"),
	REPAIR(2,"维修","REP_APPLY_REPAIR"),
	CHECK(3,"验收","REP_APPLY_CHECK");
	
	private Integer type;
	private String name;
	private String code;
	
	private WeiXinRepairMessageTypeEnum(Integer type, String name,String code) {
		this.type = type;
		this.name = name;
		this.code = code;
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

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}
	
}
