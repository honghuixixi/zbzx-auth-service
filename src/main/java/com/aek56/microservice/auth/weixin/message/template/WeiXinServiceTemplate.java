package com.aek56.microservice.auth.weixin.message.template;

/**
 * 服务平台消息模板内容
 *	
 * @author HongHui
 * @date   2017年12月7日
 */
public class WeiXinServiceTemplate {
	
	//标题
	private String first;
	//类型
	private String keyword1;
	//时间
	private String keyword2;
	//备注说明
	private String remark;
	
	public String getFirst() {
		return first;
	}
	public void setFirst(String first) {
		this.first = first;
	}
	public String getKeyword1() {
		return keyword1;
	}
	public void setKeyword1(String keyword1) {
		this.keyword1 = keyword1;
	}
	public String getKeyword2() {
		return keyword2;
	}
	public void setKeyword2(String keyword2) {
		this.keyword2 = keyword2;
	}
	public String getRemark() {
		return remark;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
	
}
