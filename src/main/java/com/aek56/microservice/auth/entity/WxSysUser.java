package com.aek56.microservice.auth.entity;

import java.util.Date;

import com.aek56.microservice.auth.common.DataEntity;

/**
 * 微信用户与设备用户绑定关系
 *	
 * @author HongHui
 * @date   2017年12月4日
 */
public class WxSysUser extends DataEntity{

	private static final long serialVersionUID = -7443719330598953524L;
	
	//用户ID
	private Long userId;
	//用户密码
	private String password;
	//只有在用户将公众号绑定到微信开放平台帐号后，才会出现该字段
	private String unionId;
	//微信公众号OpenId
	private String openId;
	//小程序用户OpenId
	private String miniOpenId;
	//绑定日期
	private Date createTime;
	//是否启用
	private Boolean enable;
	
	public Long getUserId() {
		return userId;
	}
	public void setUserId(Long userId) {
		this.userId = userId;
	}
	public String getOpenId() {
		return openId;
	}
	public void setOpenId(String openId) {
		this.openId = openId;
	}
	public Date getCreateTime() {
		return createTime;
	}
	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getUnionId() {
		return unionId;
	}
	public void setUnionId(String unionId) {
		this.unionId = unionId;
	}
	public String getMiniOpenId() {
		return miniOpenId;
	}
	public void setMiniOpenId(String miniOpenId) {
		this.miniOpenId = miniOpenId;
	}
	public Boolean getEnable() {
		return enable;
	}
	public void setEnable(Boolean enable) {
		this.enable = enable;
	}
	@Override
	public String toString() {
		return "WxSysUser [userId=" + userId + ", password=" + password + ", unionId=" + unionId + ", openId=" + openId
				+ ", miniOpenId=" + miniOpenId + ", createTime=" + createTime + ", enable=" + enable + "]";
	}
}
