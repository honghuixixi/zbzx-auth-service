package com.aek56.microservice.auth.mapper;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.aek56.microservice.auth.dao.CrudDao;
import com.aek56.microservice.auth.entity.SysRole;
import com.aek56.microservice.auth.entity.SysTenant;

/**
 * 角色DAO接口
 *
 * @author zj@aek56.com
 */
@Mapper
public interface SysRoleMapper extends CrudDao<SysRole>
{
    
    /**
     * 查询用户角色列表
     */
    List<SysRole> findListByUser(@Param("userId") Long userId, @Param("tenantId") Long tenantId);
    
    Integer findDataScopeByUser(@Param("userId") Long userId, @Param("tenantId") Long tenantId);
    
    List<Map<String, Object>> findDataScopeListByUser(@Param("userId") Long userId, @Param("tenantId") Long tenantId);
    
    List<SysRole> findList(@Param("tenantId") Long tenantId);
    
    Boolean isOrgAdmin(@Param("userId") Long userId, @Param("tenantId") Long tenantId);
    
    Boolean isSubOrg(@Param("parentTenantId") Long parentTenantId, @Param("subTenantId") Long subTenantId);
    
    List<Map<String, Object>> getOrgModule(@Param("userId") Long userId, @Param("tenantId") Long tenantId);
    
    List<Map<String, Object>> getOrgModuleByRole(@Param("userId") Long userId, @Param("tenantId") Long tenantId);
    
    List<Map<String, Object>> getOrg(@Param("tenantId") Long tenantId,
            @Param("parentTenantIds") String parentTenantIds);
    
    List<Map<String, Object>> getOrgByRole(@Param("userId") Long userId);
    
    Map<String, Object> getTenant(@Param("tenantId") Long tenantId);
    
    Boolean isTenantEnable(@Param("tenantId") Long tenantId);
    
    SysTenant getTenantInfo(@Param("tenantId") Long tenantId);
    
    SysTenant getTenantById(@Param("tenantId") Long tenantId);
}
