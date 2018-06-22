package com.aek56.microservice.auth.weixin.request;

import java.io.Serializable;
import java.util.List;

import org.hibernate.validator.constraints.NotEmpty;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * 微信公众号发送服务平台消息请求实体类
 *	
 * @author HongHui
 * @date   2017年12月5日
 */
@ApiModel(value = "WeiXinServiceMessageRequest", description = "服务平台消息推送")
public class  WeiXinServiceMessageRequest implements Serializable {

	private static final long serialVersionUID = 2715780059307779372L;

	//消息接收者
	@ApiModelProperty(value = "消息接收者")
    @NotEmpty
    private List<Long> tenantIds;
 
  	//消息类型0=通知，1=消息,2=文章
	@ApiModelProperty(value = "消息类型0=通知，1=消息,2=文章")
    @NotEmpty
  	private Integer type;
	
	//发布机构名称
	@ApiModelProperty(value = "发布机构名称")
    @NotEmpty
	private String publishTenantName;
	
	//发布时间
	@ApiModelProperty(value = "发布时间")
    @NotEmpty
	private String publishTime;

	public List<Long> getTenantIds() {
		return tenantIds;
	}

	public void setTenantIds(List<Long> tenantIds) {
		this.tenantIds = tenantIds;
	}

	public Integer getType() {
		return type;
	}

	public void setType(Integer type) {
		this.type = type;
	}

	public String getPublishTenantName() {
		return publishTenantName;
	}

	public void setPublishTenantName(String publishTenantName) {
		this.publishTenantName = publishTenantName;
	}

	public String getPublishTime() {
		return publishTime;
	}

	public void setPublishTime(String publishTime) {
		this.publishTime = publishTime;
	}
    
}
