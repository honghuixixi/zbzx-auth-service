package com.aek56.microservice.auth.bo;

import java.io.Serializable;

import org.springframework.web.multipart.MultipartFile;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

@ApiModel
public class UploadInfo implements Serializable {

	@ApiModelProperty(required=true)
	private MultipartFile[] files;
	@ApiModelProperty(value="是否保留原文件名(默认:格式化;1:保留)", dataType="int", allowableValues=",0,1")
	private int holdOringName=0;//保留原文件名(默认:格式化,1:保留)

	public MultipartFile[] getFiles() {
		return files;
	}
	public void setFiles(MultipartFile[] files) {
		this.files = files;
	}
	public int getHoldOringName() {
		return holdOringName;
	}
	public void setHoldOringName(int holdOringName) {
		this.holdOringName = holdOringName;
	}
	
}
