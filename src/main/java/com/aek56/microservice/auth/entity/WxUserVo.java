package com.aek56.microservice.auth.entity;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

@ApiModel
public class WxUserVo {

	@ApiModelProperty("用户id")
	private Long id;
	
	@ApiModelProperty("登录名")
	private String loginName;
	
	@ApiModelProperty("姓名")
	private String name;
	
	@ApiModelProperty("手机号")
	private String mobile;
	
	@ApiModelProperty("所属机构id")
	private String tenantId;
	
	@ApiModelProperty("所属机构名称")
	private String tenantName;
	
	@ApiModelProperty("所属部门名称")
	private String deptName;
	
	@ApiModelProperty("上级行政机构名称")
	private String manageTenantName;
	
	@ApiModelProperty("是否接受消息")
	private Boolean isRcvMsg;
	
	@ApiModelProperty("邮箱")
	private String email;
	
	@ApiModelProperty("所在机构类型")
	private Integer tenantType;

	public String getLoginName() {
		return loginName;
	}

	public void setLoginName(String loginName) {
		this.loginName = loginName;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getMobile() {
		return mobile;
	}

	public void setMobile(String mobile) {
		this.mobile = mobile;
	}

	public String getTenantId() {
		return tenantId;
	}

	public void setTenantId(String tenantId) {
		this.tenantId = tenantId;
	}

	public String getTenantName() {
		return tenantName;
	}

	public void setTenantName(String tenantName) {
		this.tenantName = tenantName;
	}

	public String getDeptName() {
		return deptName;
	}

	public void setDeptName(String deptName) {
		this.deptName = deptName;
	}

	public String getManageTenantName() {
		return manageTenantName;
	}

	public void setManageTenantName(String manageTenantName) {
		this.manageTenantName = manageTenantName;
	}

	public Boolean getIsRcvMsg() {
		return isRcvMsg;
	}

	public void setIsRcvMsg(Boolean isRcvMsg) {
		this.isRcvMsg = isRcvMsg;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Integer getTenantType() {
		return tenantType;
	}

	public void setTenantType(Integer tenantType) {
		this.tenantType = tenantType;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}
	
	
	
}
