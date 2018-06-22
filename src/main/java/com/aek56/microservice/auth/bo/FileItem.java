package com.aek56.microservice.auth.bo;

/**
 * 文件路径及文件名称
 *	
 * @author HongHui
 * @date   2017年11月6日
 */
public class FileItem {
	
	private String fileName;
	private String uploadUrl;
	
	public FileItem(String fileName, String uploadUrl) {
		this.fileName = fileName;
		this.uploadUrl = uploadUrl;
	}
	
	public String getFileName() {
		return fileName;
	}
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
	public String getUploadUrl() {
		return uploadUrl;
	}
	public void setUploadUrl(String uploadUrl) {
		this.uploadUrl = uploadUrl;
	}
	
	
}
