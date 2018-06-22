package com.aek56.microservice.auth.entity;

import com.aek56.microservice.auth.common.DataEntity;

/**
 * 菜单Entity
 *
 * @author zj@aek56.com
 */
public class SysMenu extends DataEntity
{
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 父级编号
     */
    private String parentId;
    
    /**
     * 名称
     */
    private String name;
	private Long moduleId;
	/**
	/**
	 * 权限标识
	 */
	private String code;
    
    /**
     * 链接
     */
    private String url;
	/**
	 * target
	 */
	private String target;
	/**
	 * 菜单标识
	 */
	private Boolean menuFlag;

    /**
     * 图标
     */
    private String icon;

	public String getParentId() {
		return parentId;
	}

	public void setParentId(String parentId) {
		this.parentId = parentId;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Long getModuleId() {
		return moduleId;
	}

	public void setModuleId(Long moduleId) {
		this.moduleId = moduleId;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getTarget() {
		return target;
	}

	public void setTarget(String target) {
		this.target = target;
	}

	public Boolean getMenuFlag() {
		return menuFlag;
	}

	public void setMenuFlag(Boolean menuFlag) {
		this.menuFlag = menuFlag;
	}

	public String getIcon() {
		return icon;
	}

	public void setIcon(String icon) {
		this.icon = icon;
	}
    
    
}