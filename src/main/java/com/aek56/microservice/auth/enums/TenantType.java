package com.aek56.microservice.auth.enums;

/**
 * 租户类型
 * 
 * @author Mr.han
 *
 */
public enum TenantType {

	/** AEK系统 */
	SYSTEM("AEK系统", 0),
	
	/** 医疗机构 */
	HOSPITAL("医疗机构", 1),

	/** 监管机构 */
	SUPERVISE("监管机构", 2),
	
	/** 供应商*/
	SUPPLIER("供应商",3);

	private String title;

	private Integer number;

	private TenantType(String title, Integer number) {
		this.title = title;
		this.setNumber(number);
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public Integer getNumber() {
		return number;
	}

	public void setNumber(Integer number) {
		this.number = number;
	}
}
