package com.aek56.microservice.auth.weixin;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.aek56.microservice.auth.entity.SysUser;
import com.aek56.microservice.auth.mapper.SysUserMapper;
import com.aek56.microservice.auth.weixin.message.template.WeiXinRepairMessageTypeEnum;

/**
 *  用户服务
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
@Service
@Transactional
public class SysUserService {
	
	@Autowired
	private SysUserMapper sysUserMapper;
	
	/**
	 * 根据机构ID和业务类型查询拥有相应权限的用户集合
	 * @param tenantId 机构ID
	 * @param type     1=接单，2=维修，3=验收
	 * @return
	 */
	public List<SysUser> getWeiXinRepairMessageUsers(Long tenantId,Integer type){
		String code = WeiXinRepairMessageTypeEnum.TAKE_ORDER.getCode();
		//接单
		if(type.equals(WeiXinRepairMessageTypeEnum.TAKE_ORDER.getType())){
			code = WeiXinRepairMessageTypeEnum.TAKE_ORDER.getCode();
		}
		//维修
		if(type.equals(WeiXinRepairMessageTypeEnum.REPAIR.getType())){
			code = WeiXinRepairMessageTypeEnum.REPAIR.getCode();
		}
		//验收
		if(type.equals(WeiXinRepairMessageTypeEnum.CHECK.getType())){
			code = WeiXinRepairMessageTypeEnum.CHECK.getCode();
		}
		return sysUserMapper.getUserByTenantIdAndPermissionCode(tenantId, code);
	}
}
