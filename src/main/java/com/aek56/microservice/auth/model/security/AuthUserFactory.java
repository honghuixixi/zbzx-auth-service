package com.aek56.microservice.auth.model.security;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.aek56.microservice.auth.common.StringHelper;
import com.aek56.microservice.auth.entity.SysMenu;
import com.aek56.microservice.auth.entity.SysRole;
import com.aek56.microservice.auth.entity.SysUser;

/**
 * The type Auth user factory.
 *
 * @author zj@aek56.com
 */
public final class AuthUserFactory
{
    
    private AuthUserFactory()
    {
    }
    
    /**
     * Create auth user.
     *
     * @param user the user
     * @return the auth user
     */
    public static AuthUser create(SysUser user)
    {
        AuthUser authUser = new AuthUser(user.getId());
        authUser.setLoginName(user.getLoginName());
        authUser.setRealName(user.getRealName());
        authUser.setEmail(user.getEmail());
        authUser.setMobile(user.getMobile());
        authUser.setPassword(user.getPassword());
        authUser.setEnabled(user.getEnable());
        authUser.setTenantId(user.getTenantId());
        authUser.setTenantName(user.getTenantName());
        authUser.setDeviceId(user.getDeviceId());
        authUser.setAuthorities(mapToGrantedAuthorities(user.getRoles(), user.getMenus()));
        authUser.setModules(user.getModules());
        authUser.setOrgs(user.getOrgs());
        authUser.setMenus(user.getMenus());
        authUser.setDeptId(user.getDeptId());
        authUser.setDeptName(user.getDeptName());
        authUser.setAdminFlag(user.getAdminFlag());
        authUser.setTenantType(user.getTenantType());
        authUser.setDataScope(user.getDataScope());
        authUser.setParentDeptIds(user.getParentDeptIds());
        authUser.setDeptIds(user.getDeptIds());
        return authUser;
    }
    
    /**
     * Create auth user.
     *
     * @param user the user
     * @return the auth user
     */
    public static AuthUser create(SysUser user,Map<String,Object> currentTenant )
    {
    	AuthUser authUser = AuthUserFactory.create(user);
    	if(null != currentTenant){
    		authUser.setTenantId(Long.parseLong(currentTenant.get("id").toString()));
            authUser.setTenantName(currentTenant.get("name").toString());
            authUser.setTenantType(Integer.parseInt(currentTenant.get("tenant_type").toString()));
            authUser.setTenantLicense(currentTenant.get("license") == null ? null : currentTenant.get("license").toString());
    	}
        return authUser;
    }
    
    /**
     * 权限转换
     *
     * @param sysRoles 角色列表
     * @param sysMenus 菜单列表
     * @return 权限列表
     */
    private static List<SimpleGrantedAuthority> mapToGrantedAuthorities(List<SysRole> sysRoles, List<SysMenu> sysMenus)
    {
        
        List<SimpleGrantedAuthority> authorities = sysRoles.stream()
                .filter(SysRole::getEnable)
                .map(sysRole -> new SimpleGrantedAuthority(sysRole.getCode()))
                .collect(Collectors.toList());
        
        // 添加基于Permission的权限信息
        sysMenus.stream().filter(menu -> StringHelper.isNotBlank(menu.getCode())).forEach(menu -> {
            // 添加基于Permission的权限信息
            for (String permission : StringHelper.split(menu.getCode(), ","))
            {
                authorities.add(new SimpleGrantedAuthority(permission));
            }
        });
        
        return authorities;
    }
    
}
