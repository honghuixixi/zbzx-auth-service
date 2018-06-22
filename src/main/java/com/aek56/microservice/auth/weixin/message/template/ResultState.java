package com.aek56.microservice.auth.weixin.message.template;

import java.io.Serializable;

/**
 * 微信API返回状态
 *	
 * @author HongHui
 * @date   2017年12月4日
 */
public class ResultState implements Serializable {

	private static final long serialVersionUID = -1280674112678216941L;
	// 状态  
	private int errcode; 
	 //信息 
    private String errmsg;
    
	public int getErrcode() {
		return errcode;
	}
	public void setErrcode(int errcode) {
		this.errcode = errcode;
	}
	public String getErrmsg() {
		return errmsg;
	}
	public void setErrmsg(String errmsg) {
		this.errmsg = errmsg;
	}
	
	@Override
	public String toString() {
		return "ResultState [errcode=" + errcode + ", errmsg=" + errmsg + "]";
	}
	
}
