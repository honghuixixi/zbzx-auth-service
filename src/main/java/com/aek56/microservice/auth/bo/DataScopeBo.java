package com.aek56.microservice.auth.bo;

import java.util.List;

/**
 * 数据范围bean
 *	
 * @author HongHui
 * @date   2017年9月22日
 */
public class DataScopeBo {

	private Integer dataScope;
	private List<Long> definedDeptIds;
	
	public DataScopeBo(Integer dataScope, List<Long> definedDeptIds) {
		this.dataScope = dataScope;
		this.definedDeptIds = definedDeptIds;
	}

	public Integer getDataScope() {
		return dataScope;
	}

	public void setDataScope(Integer dataScope) {
		this.dataScope = dataScope;
	}

	public List<Long> getDefinedDeptIds() {
		return definedDeptIds;
	}

	public void setDefinedDeptIds(List<Long> definedDeptIds) {
		this.definedDeptIds = definedDeptIds;
	}
	
}
