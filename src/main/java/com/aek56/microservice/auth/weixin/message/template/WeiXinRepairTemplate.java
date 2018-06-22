package com.aek56.microservice.auth.weixin.message.template;

import java.io.Serializable;

/**
 * 维修消息模板内容
 *	
 * @author HongHui
 * @date   2017年12月7日
 */
public class WeiXinRepairTemplate implements Serializable {
	
	private static final long serialVersionUID = -3870398146825118145L;
	//标题
	private String first;
	//维修单号
	private String keyword1;
	//设备名称
	private String keyword2;
	//设备编号
	private String keyword3;
	//所在部门
	private String keyword4;
	//申请人
	private String keyword5;
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
	public String getKeyword3() {
		return keyword3;
	}
	public void setKeyword3(String keyword3) {
		this.keyword3 = keyword3;
	}
	public String getKeyword4() {
		return keyword4;
	}
	public void setKeyword4(String keyword4) {
		this.keyword4 = keyword4;
	}
	public String getKeyword5() {
		return keyword5;
	}
	public void setKeyword5(String keyword5) {
		this.keyword5 = keyword5;
	}
	public String getRemark() {
		return remark;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
	
}
