package com.aek56.microservice.auth.common;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

@ApiModel(value = "Result", description = "")
public class Result<T> {

	public Result() {
	}

	public Result(String code, String msg) {
		this.code = code;
		this.msg = msg;
	}

	public Result(String code, String msg, T data) {
		this.code = code;
		this.msg = msg;
		this.data = data;
	}

	@ApiModelProperty(value = "状态码.200(OK)")
	private String code;

	@ApiModelProperty(value = "返回的消息")
	private String msg;

	@ApiModelProperty(value = "返回的数据")
	private T data;

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	public T getData() {
		return data;
	}

	public void setData(T data) {
		this.data = data;
	}

}
