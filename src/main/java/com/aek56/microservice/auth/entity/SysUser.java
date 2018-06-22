package com.aek56.microservice.auth.entity;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.Length;

import com.aek56.microservice.auth.common.DataEntity;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 用户Entity
 *
 * @author zj@aek56.com
 */
public class SysUser extends DataEntity {

	private static final long serialVersionUID = 1L;

	/**
	 * 设备Id
	 */
	private String deviceId;

	/**
	 * 登录名
	 */
	private String loginName;

	/**
	 * 机构Id
	 */
	private Long tenantId;

	/**
	 * 机构类型 [1=医疗机构,2=监管机构,3=设备供应商,4=设备维修商,5=配件供应商]
	 */
	private int tenantType;

	/**
	 * 密码
	 */
	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	private String password;

	/**
	 * 所属租户名称
	 */
	private String tenantName;

	/**
	 * 真实姓名
	 */
	private String realName;

	/**
	 * 归属部门ID
	 */
	private Long deptId;

	/**
	 * 归属部门名称
	 */
	private String deptName;

	/**
	 * 邮箱
	 */
	private String email;

	/**
	 * 手机
	 */
	private String mobile;

	/**
	 * 是否可用
	 */
	private Boolean enable;

	/**
	 * 是否被删除
	 */
	private Boolean delFlag;

	/**
	 * 是否管理员(0:否;1:是)
	 */
	private Boolean adminFlag;

	/**
	 * 所有上级部门ID
	 */
	private String parentDeptIds;

	/**
	 * 所有下级部门ID
	 */
	private List<Long> deptIds;

	/**
	 * 用户注册IP
	 */
	private String registrationIp;

	/**
	 * 最后登录IP
	 */
	private String lastLoginIp;

	/**
	 * 最后登录时间
	 */
	private Date lastLoginTime;

	/**
	 * 最后登录平台
	 */
	private String lastClientType;

	/**
	 * 角色列表
	 */
	private List<SysRole> roles = new ArrayList<>();

	/**
	 * 菜单列表
	 */
	private List<SysMenu> menus = new ArrayList<>();

	/**
	 * 模块列表
	 */
	private List<Map<String, Object>> modules = new ArrayList<Map<String, Object>>();

	/**
	 * 机构列表
	 */
	private List<Map<String, Object>> orgs = new ArrayList<Map<String, Object>>();

	/**
	 * 数据权限
	 */
	private Integer dataScope;

	@Length(min = 1, max = 100)
	public String getLoginName() {
		return loginName;
	}

	public void setLoginName(String loginName) {
		this.loginName = loginName;
	}

	@Length(min = 1, max = 50)
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Email
	@Length(max = 200)
	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	@Length(min = 0, max = 200)
	public String getMobile() {
		return mobile;
	}

	public void setMobile(String mobile) {
		this.mobile = mobile;
	}

	public Boolean getEnable() {
		return enable;
	}

	public void setEnable(Boolean enable) {
		this.enable = enable;
	}

	public List<SysRole> getRoles() {
		return roles;
	}

	public void setRoles(List<SysRole> roles) {
		this.roles = roles;
	}

	@JsonIgnore
	public List<SysMenu> getMenus() {
		return menus;
	}

	public void setMenus(List<SysMenu> menus) {
		this.menus = menus;
	}

	public Long getTenantId() {
		return tenantId;
	}

	public void setTenantId(Long tenantId) {
		this.tenantId = tenantId;
	}

	public String getDeviceId() {
		return deviceId;
	}

	public void setDeviceId(String deviceId) {
		this.deviceId = deviceId;
	}

	public List<Map<String, Object>> getModules() {
		return modules;
	}

	public void setModules(List<Map<String, Object>> modules) {
		this.modules = modules;
	}

	public String getTenantName() {
		return tenantName;
	}

	public void setTenantName(String tenantName) {
		this.tenantName = tenantName;
	}

	public String getRealName() {
		return realName;
	}

	public void setRealName(String realName) {
		this.realName = realName;
	}

	public Long getDeptId() {
		return deptId;
	}

	public void setDeptId(Long deptId) {
		this.deptId = deptId;
	}

	public String getDeptName() {
		return deptName;
	}

	public void setDeptName(String deptName) {
		this.deptName = deptName;
	}

	public Boolean getAdminFlag() {
		return adminFlag;
	}

	public void setAdminFlag(Boolean adminFlag) {
		this.adminFlag = adminFlag;
	}

	public List<Map<String, Object>> getOrgs() {
		return orgs;
	}

	public void setOrgs(List<Map<String, Object>> orgs) {
		this.orgs = orgs;
	}

	public String getParentDeptIds() {
		return parentDeptIds;
	}

	public void setParentDeptIds(String parentDeptIds) {
		this.parentDeptIds = parentDeptIds;
	}

	public String getRegistrationIp() {
		return registrationIp;
	}

	public void setRegistrationIp(String registrationIp) {
		this.registrationIp = registrationIp;
	}

	public String getLastLoginIp() {
		return lastLoginIp;
	}

	public void setLastLoginIp(String lastLoginIp) {
		this.lastLoginIp = lastLoginIp;
	}

	public Date getLastLoginTime() {
		return lastLoginTime;
	}

	public void setLastLoginTime(Date lastLoginTime) {
		this.lastLoginTime = lastLoginTime;
	}

	public String getLastClientType() {
		return lastClientType;
	}

	public void setLastClientType(String lastClientType) {
		this.lastClientType = lastClientType;
	}

	public int getTenantType() {
		return tenantType;
	}

	public void setTenantType(int tenantType) {
		this.tenantType = tenantType;
	}

	public Integer getDataScope() {
		return dataScope;
	}

	public void setDataScope(Integer dataScope) {
		this.dataScope = dataScope;
	}

	public List<Long> getDeptIds() {
		return deptIds;
	}

	public void setDeptIds(List<Long> deptIds) {
		this.deptIds = deptIds;
	}

	public Boolean getDelFlag() {
		return delFlag;
	}

	public void setDelFlag(Boolean delFlag) {
		this.delFlag = delFlag;
	}

}