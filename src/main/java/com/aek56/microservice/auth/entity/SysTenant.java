package com.aek56.microservice.auth.entity;

import java.util.Date;

public class SysTenant {

	protected Long id;

	/**
	 * 名称
	 */
	private String name;

	/**
	 * 管理机构ID
	 */
	private Long manageTenantId;
	
	/**
	 * 机构与上级行政单位建立关系的时间
	 */
	private Date manageTenantTime;
	
	/**
	 * 租户类型[1=医疗机构,2=监管机构,3=设备供应商,4=设备维修商,5=配件供应商]
	 */
	private Integer tenantType;

	/**
	 * 是否试用[0=试用,1=正式]
	 */
	private Integer commercialUse;

	/**
	 * 是否测试
	 */
	private Integer trial;

	/**
	 * 创建子机构数量限制(0,不可创建下级机构)
	 */
	private Integer subTenantLimit;
	
	/**
	 * 已创建下级机构数量
	 */
	private Integer subTenant;
	/**
	 * 创建用户数量限制(0,不可创建用户)
	 */
	private Integer userLimit;
	/**
	 * 租户到期时间
	 */
	private Date expireTime;
	/**
	 * 机构logo
	 */
	private String logo;
	/**
	 * 机构来源(后台创建，前台注册，渠道商创建)
	 */
	private Integer origin;

	/**
	 * 审核状态
	 */
	private Integer auditStatus;

	/**
	 * 管理员ID
	 */
	private Long adminId;

	/**
	 * 父机构ID
	 */
	private Long parentId;

	/**
	 * 所有机构ID组 1,2,5,4
	 */

	private String parentIds;

	/**
	 * 是否推送消息
	 */
	private Boolean notify;

	/**
	 * token有效期(秒)
	 */
	private Integer tokenMaxExpire;
	/**
	 * 创建者
	 */
	private Long createBy;
	/**
	 * 创建时间
	 */
	private Date createTime;
	/**
	 * 更新者
	 */
	private Long updateBy;
	/**
	 * 更新时间
	 */
	private Date updateTime;
	/**
	 * 启用标记 1 启用 0 停用
	 */
	private Boolean enable;
	/**
	 * 删除标记 1 已删除,0 未删除
	 */
	private Boolean delFlag;

	private String customData;

	/**
	 * 省
	 */
	private String province;

	/**
	 * 市
	 */
	private String city;

	/**
	 * 区(县)
	 */
	private String county;

	/**
	 * 组织机构代码
	 */
	private String license;

	private String manageTenantName;
	
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Long getManageTenantId() {
		return manageTenantId;
	}

	public void setManageTenantId(Long manageTenantId) {
		this.manageTenantId = manageTenantId;
	}

	public Date getManageTenantTime() {
		return manageTenantTime;
	}

	public void setManageTenantTime(Date manageTenantTime) {
		this.manageTenantTime = manageTenantTime;
	}

	public Integer getTenantType() {
		return tenantType;
	}

	public void setTenantType(Integer tenantType) {
		this.tenantType = tenantType;
	}

	public Integer getCommercialUse() {
		return commercialUse;
	}

	public void setCommercialUse(Integer commercialUse) {
		this.commercialUse = commercialUse;
	}

	public Integer getTrial() {
		return trial;
	}

	public void setTrial(Integer trial) {
		this.trial = trial;
	}

	public Integer getSubTenantLimit() {
		return subTenantLimit;
	}

	public void setSubTenantLimit(Integer subTenantLimit) {
		this.subTenantLimit = subTenantLimit;
	}

	public Integer getSubTenant() {
		return subTenant;
	}

	public void setSubTenant(Integer subTenant) {
		this.subTenant = subTenant;
	}

	public Integer getUserLimit() {
		return userLimit;
	}

	public void setUserLimit(Integer userLimit) {
		this.userLimit = userLimit;
	}

	public Date getExpireTime() {
		return expireTime;
	}

	public void setExpireTime(Date expireTime) {
		this.expireTime = expireTime;
	}

	public String getLogo() {
		return logo;
	}

	public void setLogo(String logo) {
		this.logo = logo;
	}

	public Integer getOrigin() {
		return origin;
	}

	public void setOrigin(Integer origin) {
		this.origin = origin;
	}

	public Integer getAuditStatus() {
		return auditStatus;
	}

	public void setAuditStatus(Integer auditStatus) {
		this.auditStatus = auditStatus;
	}

	public Long getAdminId() {
		return adminId;
	}

	public void setAdminId(Long adminId) {
		this.adminId = adminId;
	}

	public Long getParentId() {
		return parentId;
	}

	public void setParentId(Long parentId) {
		this.parentId = parentId;
	}

	public String getParentIds() {
		return parentIds;
	}

	public void setParentIds(String parentIds) {
		this.parentIds = parentIds;
	}

	public Boolean getNotify() {
		return notify;
	}

	public void setNotify(Boolean notify) {
		this.notify = notify;
	}

	public Integer getTokenMaxExpire() {
		return tokenMaxExpire;
	}

	public void setTokenMaxExpire(Integer tokenMaxExpire) {
		this.tokenMaxExpire = tokenMaxExpire;
	}

	public Long getCreateBy() {
		return createBy;
	}

	public void setCreateBy(Long createBy) {
		this.createBy = createBy;
	}

	public Date getCreateTime() {
		return createTime;
	}

	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}

	public Long getUpdateBy() {
		return updateBy;
	}

	public void setUpdateBy(Long updateBy) {
		this.updateBy = updateBy;
	}

	public Date getUpdateTime() {
		return updateTime;
	}

	public void setUpdateTime(Date updateTime) {
		this.updateTime = updateTime;
	}

	public Boolean getEnable() {
		return enable;
	}

	public void setEnable(Boolean enable) {
		this.enable = enable;
	}

	public Boolean getDelFlag() {
		return delFlag;
	}

	public void setDelFlag(Boolean delFlag) {
		this.delFlag = delFlag;
	}

	public String getCustomData() {
		return customData;
	}

	public void setCustomData(String customData) {
		this.customData = customData;
	}

	public String getProvince() {
		return province;
	}

	public void setProvince(String province) {
		this.province = province;
	}

	public String getCity() {
		return city;
	}

	public void setCity(String city) {
		this.city = city;
	}

	public String getCounty() {
		return county;
	}

	public void setCounty(String county) {
		this.county = county;
	}

	public String getLicense() {
		return license;
	}

	public void setLicense(String license) {
		this.license = license;
	}

	public String getManageTenantName() {
		return manageTenantName;
	}

	public void setManageTenantName(String manageTenantName) {
		this.manageTenantName = manageTenantName;
	}


}
