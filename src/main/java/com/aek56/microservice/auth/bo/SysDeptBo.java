package com.aek56.microservice.auth.bo;

/**
 *  部门bean
 *
 * @author  Honghui
 * @date    2017年9月22日
 * @version 1.0
 */
public class SysDeptBo {

	private Long deptId;
	private String deptName;
	
	public Long getDeptId() {
		return deptId;
	}
	public void setDeptId(Long deptId) {
		this.deptId = deptId;
	}
	public String getDeptName() {
		return deptName;
	}
	public void setDeptName(String deptName) {
		this.deptName = deptName;
	}
	
}
