package com.aek56.microservice.auth.model.security;

import java.util.List;

/**
 * 短信发送返回值
 * 
 * @author Mr.han
 *
 */
public class SmsResult {

	private Integer success;// 是否成功，1：成功；0：失败。

	private String msg;// 发送状态描述。

	private Integer errcode; // 运营商返回的状态码。

	private String batchNo;// 发送成功时的发送记录号。

	private List<String> failList;// 发送失败的手机号列表

	private Integer success2;// 是否成功记录日志，1：成功；0：失败。

	private String msg2; // 记录日志结果描述。

	/**
	 * @return the success
	 */
	public Integer getSuccess() {
		return success;
	}

	/**
	 * @param success
	 *            the success to set
	 */
	public void setSuccess(Integer success) {
		this.success = success;
	}

	/**
	 * @return the msg
	 */
	public String getMsg() {
		return msg;
	}

	/**
	 * @param msg
	 *            the msg to set
	 */
	public void setMsg(String msg) {
		this.msg = msg;
	}

	/**
	 * @return the errcode
	 */
	public Integer getErrcode() {
		return errcode;
	}

	/**
	 * @param errcode
	 *            the errcode to set
	 */
	public void setErrcode(Integer errcode) {
		this.errcode = errcode;
	}

	/**
	 * @return the failList
	 */
	public List<String> getFailList() {
		return failList;
	}

	/**
	 * @param failList
	 *            the failList to set
	 */
	public void setFailList(List<String> failList) {
		this.failList = failList;
	}

	/**
	 * @return the success2
	 */
	public Integer getSuccess2() {
		return success2;
	}

	/**
	 * @param success2
	 *            the success2 to set
	 */
	public void setSuccess2(Integer success2) {
		this.success2 = success2;
	}

	/**
	 * @return the msg2
	 */
	public String getMsg2() {
		return msg2;
	}

	/**
	 * @param msg2
	 *            the msg2 to set
	 */
	public void setMsg2(String msg2) {
		this.msg2 = msg2;
	}

	public String getBatchNo() {
		return batchNo;
	}

	public void setBatchNo(String batchNo) {
		this.batchNo = batchNo;
	}

}
