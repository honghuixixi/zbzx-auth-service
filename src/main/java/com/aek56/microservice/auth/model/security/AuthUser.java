package com.aek56.microservice.auth.model.security;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.aek56.microservice.auth.entity.SysMenu;
import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * Security User
 *
 * @author zj@aek56.com
 */
public class AuthUser extends AbstractAuthUser
{
    
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    
    /**
     * id
     */
    private Long id;
    
    /**
     * 设备Id
     */
    
    private String deviceId;
    
    /**
     * 登录名
     */
    private String loginName;
    
    /**
     * 机构Id
     */
    private Long tenantId;
    
    /**
     * 机构类型    [1=医疗机构,2=监管机构,3=设备供应商,4=设备维修商,5=配件供应商]
     */
    private int tenantType;
    
    /**
     * 密码
     */
    private String password;
    
    /**
     * 所属租户名称
     */
    private String tenantName;
    
    /**
     * 真实姓名
     */
    private String realName;
    
    /**
     * 归属部门ID
     */
    private Long deptId;
    
    /**
     * 归属部门名称
     */
    private String deptName;
    
    /**
     * 邮箱
     */
    private String email;
    
    /**
     * 手机
     */
    private String mobile;
    
    /**
     * 权限
     */
    private Collection<SimpleGrantedAuthority> authorities;
    
    /**
     * 权限
     */
    private String authoritiesStr;
    
    /**
     * 数据权限
     */
    private Integer dataScope;
    
    /**
     * 所有上级部门ID
     */
    private String parentDeptIds;
    
    /**
     * 所属机构组织代码
     */
    private String tenantLicense;
    
    /**
     * 子部门及其子部门
     */
    private List<Long> deptIds;
    
    public String getAuthoritiesStr()
    {
        StringBuilder bf = new StringBuilder();
        if (authorities != null && authorities.size() > 0)
        {
            Iterator<SimpleGrantedAuthority> it = authorities.iterator();
            while (it.hasNext())
            {
                String authority = it.next().getAuthority();
                bf.append(authority);
                bf.append(",");
            }
            return bf.substring(0, bf.length() - 1);
        }
        return authoritiesStr;
    }
    
    public void setAuthoritiesStr(String authoritiesStr)
    {
        this.authoritiesStr = authoritiesStr;
    }
    
    /**
     * 模块列表
     */
    private List<Map<String, Object>> modules;
    
    /**
     * 机构列表
     */
    private List<Map<String, Object>> orgs;
    
    /**
     * 菜单列表
     */
    private List<SysMenu> menus;
    
    /**
     * 锁定
     */
    private boolean enabled;
    
    //管理员标识
    
    private boolean adminFlag;
    //上次权限修改时间
    
    public AuthUser(Long id)
    {
        this.id = id;
    }
    
    public boolean isAdminFlag()
    {
        return adminFlag;
    }
    
    public void setAdminFlag(boolean adminFlag)
    {
        this.adminFlag = adminFlag;
    }
    
    public Long getId()
    {
        return id;
    }
    
    public void setId(Long id)
    {
        this.id = id;
    }
    
    @Override
    public String getUsername()
    {
        return loginName;
    }
    
    public String getLoginName()
    {
        return loginName;
    }
    
    public void setLoginName(String loginName)
    {
        this.loginName = loginName;
    }
    
    @JsonIgnore
    @Override
    public String getPassword()
    {
        return password;
    }
    
    public void setPassword(String password)
    {
        this.password = password;
    }
    
    public void setEmail(String email)
    {
        this.email = email;
    }
    
    public void setMobile(String mobile)
    {
        this.mobile = mobile;
    }
    
    public void setAuthorities(Collection<SimpleGrantedAuthority> authorities)
    {
        this.authorities = authorities;
    }
    
    public void setEnabled(boolean enabled)
    {
        this.enabled = enabled;
    }
    
    public String getEmail()
    {
        return email;
    }
    
    public String getMobile()
    {
        return mobile;
    }
    
    @Override
    public Collection<SimpleGrantedAuthority> getAuthorities()
    {
        return authorities;
    }
    
    @Override
    public boolean isEnabled()
    {
        return enabled;
    }
    
    public Long getTenantId()
    {
        return tenantId;
    }
    
    public void setTenantId(Long tenantId)
    {
        this.tenantId = tenantId;
    }
    
    public String getDeviceId()
    {
        return deviceId;
    }
    
    public void setDeviceId(String deviceId)
    {
        this.deviceId = deviceId;
    }
    
    public List<Map<String, Object>> getModules()
    {
        return modules;
    }
    
    public void setModules(List<Map<String, Object>> modules)
    {
        this.modules = modules;
    }
    
    public String getTenantName()
    {
        return tenantName;
    }
    
    public void setTenantName(String tenantName)
    {
        this.tenantName = tenantName;
    }
    
    public String getRealName()
    {
        return realName;
    }
    
    public void setRealName(String realName)
    {
        this.realName = realName;
    }
    
    public Long getDeptId()
    {
        return deptId;
    }
    
    public void setDeptId(Long deptId)
    {
        this.deptId = deptId;
    }
    
    public String getDeptName()
    {
        return deptName;
    }
    
    public void setDeptName(String deptName)
    {
        this.deptName = deptName;
    }
    
    public List<Map<String, Object>> getOrgs()
    {
        return orgs;
    }
    
    public void setOrgs(List<Map<String, Object>> orgs)
    {
        this.orgs = orgs;
    }
    
    public List<SysMenu> getMenus()
    {
        return menus;
    }
    
    public void setMenus(List<SysMenu> menus)
    {
        this.menus = menus;
    }
    
    public int getTenantType()
    {
        return tenantType;
    }
    
    public void setTenantType(int tenantType)
    {
        this.tenantType = tenantType;
    }
    
    public Integer getDataScope()
    {
        return dataScope;
    }
    
    public void setDataScope(Integer dataScope)
    {
        this.dataScope = dataScope;
    }
    
    public String getParentDeptIds()
    {
        return parentDeptIds;
    }
    
    public void setParentDeptIds(String parentDeptIds)
    {
        this.parentDeptIds = parentDeptIds;
    }

	public String getTenantLicense() {
		return tenantLicense;
	}

	public void setTenantLicense(String tenantLicense) {
		this.tenantLicense = tenantLicense;
	}

	public List<Long> getDeptIds() {
		return deptIds;
	}

	public void setDeptIds(List<Long> deptIds) {
		this.deptIds = deptIds;
	}
    
}
