package com.aek56.microservice.auth.mapper;


import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.aek56.microservice.auth.dao.CrudDao;
//import com.aek56.microservice.auth.entity.SysTenant;
import com.aek56.microservice.auth.entity.SysUser;

/**
 * 用户DAO接口
 *
 * @author zj@aek56.com
 */
@Mapper
public interface SysUserMapper extends CrudDao<SysUser> {

    /**
     * 根据登录名称查询用户
     *
     * @param loginName 登录名
     * @return SysUser by login name
     */
    SysUser getByLoginName(@Param("loginName")String loginName);
    
    /**
     * 只支持登录名
     * @param loginName
     * @return
     */
    SysUser getUserByLoginName(@Param("loginName")String loginName);
    
    SysUser getUserByLoginIdNoTenant(@Param("loginId")String loginId);
    
    List<SysUser> getUserByTenantIds(@Param("tenantIds")List<Long> tenantIds);

    List<Map<String, Object>> getUsersByRole(@Param("roleId")Long roleId);

	SysUser getByMobile(@Param("mobile")String mobile);
	
	List<Long> getSubTenantList(@Param("perttern")String perttern); 
	
	void updateLoginInfo (Map<String, Object> map);
	
	void updatePassword(Map<String, Object> map);
	
	List<Long> getSubDeptIds(@Param("deptId")Long deptId,@Param("tenantId")Long tenantId);
	
	/**
	 * 查询某机构下拥有指定权限的用户
	 * @param tenantId
	 * @param permissionCode
	 * @return
	 */
	List<SysUser> getUserByTenantIdAndPermissionCode(@Param("tenantId")Long tenantId,@Param("permissionCode") String permissionCode);
	
	SysUser selectById(@Param("userId")Long userId);
}
