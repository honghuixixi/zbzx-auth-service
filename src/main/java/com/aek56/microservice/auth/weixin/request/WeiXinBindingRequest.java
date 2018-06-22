package com.aek56.microservice.auth.weixin.request;

import java.io.Serializable;

import org.hibernate.validator.constraints.NotEmpty;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * 微信绑定系统用户请求实体类
 *	
 * @author HongHui
 * @date   2017年12月5日
 */
@ApiModel(value = "WeiXinBindingRequest", description = "微信绑定系统用户请求实体类")
public class WeiXinBindingRequest implements Serializable {

	private static final long serialVersionUID = 84064067978344969L;
 
	//用户名
	@ApiModelProperty(value = "用户名")
    @NotEmpty
	private String username;
    //密码
	@ApiModelProperty(value = "密码")
    @NotEmpty
    private String password;
    //微信公众号用户OpenId
	@ApiModelProperty(value = "微信公众号用户OpenId")
    @NotEmpty
    private String openId;
	//微信公众号用户UnionId
	@ApiModelProperty(value = "微信公众号用户UnionId")
    private String unionId;
	
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getOpenId() {
		return openId;
	}
	public void setOpenId(String openId) {
		this.openId = openId;
	}
	public String getUnionId() {
		return unionId;
	}
	public void setUnionId(String unionId) {
		this.unionId = unionId;
	}
}
