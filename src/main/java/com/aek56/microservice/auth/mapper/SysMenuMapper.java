package com.aek56.microservice.auth.mapper;


import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.aek56.microservice.auth.dao.CrudDao;
import com.aek56.microservice.auth.entity.SysMenu;

/**
 * 菜单DAO接口
 *
 * @author zj@aek56.com
 */
@Mapper
public interface SysMenuMapper extends CrudDao<SysMenu> {

	List<SysMenu> findListByOrg(@Param("tenantId")Long tenantId);

    /**
     * 根据角色查询菜单
     *
     */
    List<SysMenu> findListByRole(@Param("userId")Long userId, @Param("tenantId")Long tenantId);

}
