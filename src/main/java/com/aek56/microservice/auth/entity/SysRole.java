package com.aek56.microservice.auth.entity;

import java.util.ArrayList;
import java.util.List;

import org.hibernate.validator.constraints.Length;

import com.aek56.microservice.auth.common.DataEntity;

/**
 * 角色Entity
 *
 * @author zj@aek56.com
 */
public class SysRole extends DataEntity
{
	private static final long serialVersionUID = 1L;

	/**
     * 名称
     */
    private String name;
    
    /**
     * 是否可用
     */
    private Boolean enable;
	/**
	 * 角色标识
	 */
	private String code;
    
    /**
     * 备注
     */
    private String remarks;
    
    /**
     * 菜单列表
     */
    private List<SysMenu> menus = new ArrayList<>();
    
    /**
     * 数据权限
     */
    private Integer dataScope;
    
    @Length(min = 1, max = 100)
    public String getName()
    {
        return name;
    }
    
    public void setName(String name)
    {
        this.name = name;
    }
    
    public Boolean getEnable()
    {
        return enable;
    }
    
    public void setEnable(Boolean enable)
    {
        this.enable = enable;
    }
    
    @Length(min = 0, max = 255)
    public String getRemarks()
    {
        return remarks;
    }
    
    public void setRemarks(String remarks)
    {
        this.remarks = remarks;
    }
    
    public List<SysMenu> getMenus()
    {
        return menus;
    }
    
    public void setMenus(List<SysMenu> menus)
    {
        this.menus = menus;
    }

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public Integer getDataScope() {
		return dataScope;
	}

	public void setDataScope(Integer dataScope) {
		this.dataScope = dataScope;
	}
	
}
