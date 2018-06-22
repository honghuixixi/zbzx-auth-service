package com.aek56.microservice.auth.weixin.request;

import java.io.Serializable;

import org.hibernate.validator.constraints.NotEmpty;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * 微信公众号自动登录请求实体类
 *	
 * @author HongHui
 * @date   2017年12月5日
 */
@ApiModel(value = "WeiXinAutoLoginRequest", description = "微信公众号自动登录请求实体类")
public class  WeiXinAutoLoginRequest implements Serializable {

	private static final long serialVersionUID = 7763384100823889072L;
    
	//终端ID
	@ApiModelProperty(value = "终端ID")
    @NotEmpty
    private String deviceId;
    
    //微信公众号openId
	@ApiModelProperty(value = "微信用户授权后获取的code")
    @NotEmpty
    private String code;

	public String getDeviceId() {
		return deviceId;
	}

	public void setDeviceId(String deviceId) {
		this.deviceId = deviceId;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

}
