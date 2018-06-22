package com.aek56.microservice.auth.security.service;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.aek56.microservice.auth.bo.VerifyCode;
import com.aek56.microservice.auth.common.BeanMapper;
import com.aek56.microservice.auth.entity.SysMenu;
import com.aek56.microservice.auth.entity.SysRole;
import com.aek56.microservice.auth.entity.SysTenant;
import com.aek56.microservice.auth.entity.SysUser;
import com.aek56.microservice.auth.entity.WxUserVo;
import com.aek56.microservice.auth.mapper.SysMenuMapper;
import com.aek56.microservice.auth.mapper.SysRoleMapper;
import com.aek56.microservice.auth.mapper.SysUserMapper;
import com.aek56.microservice.auth.mapper.WxSysUserMapper;
import com.aek56.microservice.auth.redis.RedisRepository;
import com.aek56.microservice.auth.security.JwtTokenUtil;
import com.aek56.microservice.auth.util.ThreadHolder;
import com.alibaba.fastjson.JSON;

/**
 * 系统管理，安全相关实体的管理类,包括用户、角色、菜单.
 *
 * @author zj@aek56.com
 */
@Service
@Transactional
public class SystemService {
	
	private static final Log logger = LogFactory.getLog(SystemService.class);

	private String remoteIp;

	@Autowired
	private SysUserMapper sysUserMapper;

	@Autowired
	private SysRoleMapper sysRoleMapper;

	@Autowired
	private SysMenuMapper sysMenuMapper;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private RedisRepository redisRepository;

	@Autowired
	public PasswordEncoder passwordEncoder;
	
	@Autowired
	public WxSysUserMapper wxSysUserMapper;
	
	public List<SysUser> getUserByTenantIds(List<Long> tenantIds){
		return sysUserMapper.getUserByTenantIds(tenantIds);
	}

	/**
	 * 根据手机号获取用户信息
	 * @param mobile
	 * @return
	 */
	public SysUser getUserByMobile(String mobile) {
		SysUser user = sysUserMapper.getByMobile(mobile);
		return user;
	}

	/**
	 * 根据登录名查询用户信息
	 * @param loginName
	 * @return
	 */
	public SysUser getUserByLoginName(String loginName) {
		SysUser user = sysUserMapper.getByLoginName(loginName);
		if (user == null) {
			return null;
		}
		// 当前部门及其子部门
		List<Long> subDeptIds = sysUserMapper.getSubDeptIds(user.getDeptId(), user.getTenantId());
		user.setDeptIds(subDeptIds);

		String deviceId = ThreadHolder.get();
		String smsLoginPwdKey = deviceId + ":loginPwd:" + user.getMobile();
		if (redisRepository.exists(smsLoginPwdKey)) {
			String smsLoginPwd = redisRepository.get(smsLoginPwdKey);
			VerifyCode currVerifyCode = JSON.parseObject(smsLoginPwd, VerifyCode.class);
			if (null != currVerifyCode && StringUtils.isNotBlank(currVerifyCode.getCode())) {
				String encyPwd = passwordEncoder.encode(currVerifyCode.getCode());
				user.setPassword(encyPwd);
			}
		}
		user.setLoginName(loginName);
		ThreadHolder.remove();
		return user;
	}

	/**
	 * 只支持登录名
	 */
	public SysUser getUserInfoByLoginName(String loginName) {
		return sysUserMapper.getUserByLoginName(loginName);
	}
	
	public SysUser getUserByLoginIdNoTenant(String loginId) {
		return sysUserMapper.getUserByLoginIdNoTenant(loginId);
	}

	public SysUser getUserById(Long userId) {
		return sysUserMapper.get(userId);
	}

	/**
	 * 初始化权限
	 * 
	 * @param user
	 * @param tenantId
	 */
	public void getPerms(SysUser user, Long tenantId) {
		if (tenantId == null || tenantId < 1) {
			tenantId = user.getTenantId();
		}
		Map<String, Object> currentTenant = this.getTenant(tenantId);
		// 判断是否有admin
		Long adminId = Long.parseLong("0");
		if (currentTenant.get("admin_id") != null) {
			adminId = Long.parseLong(currentTenant.get("admin_id").toString());
		}
		List<SysRole> roles = null;
		List<SysMenu> menuList = null;
		List<Map<String, Object>> modules = null;
		List<Map<String, Object>> orgs = null;
		boolean admin = this.isOrgAdmin(user.getId(), tenantId);
		if (user.getAdminFlag() || admin || user.getId().equals(adminId)) {// 显示机构下所有的模块
			modules = this.sysRoleMapper.getOrgModule(user.getId(), tenantId);
			menuList = sysMenuMapper.findListByOrg(tenantId);
			Map<String, Object> tenantMap = this.sysRoleMapper.getTenant(tenantId);
			logger.debug("tenantMap=" + JSON.toJSONString(tenantMap));
			if (null != tenantMap) {
				String parentIds = (String) tenantMap.get("parent_ids");
				if (StringUtils.isNotBlank(parentIds)) {
					orgs = this.sysRoleMapper.getOrg(tenantId, parentIds + "," + tenantId);
				}
			}
			roles = sysRoleMapper.findList(tenantId);
			user.setDataScope(1);// 所在机构所有数据
		} else {// 根据角色找模块
			modules = this.sysRoleMapper.getOrgModuleByRole(user.getId(), tenantId);
			menuList = sysMenuMapper.findListByRole(user.getId(), tenantId);
			orgs = this.sysRoleMapper.getOrgByRole(user.getId());
			roles = sysRoleMapper.findListByUser(user.getId(), tenantId);
		}
		// processMenu(menuList);
		user.setModules(modules);
		user.setMenus(menuList);
		user.setOrgs(orgs);
		processRole(roles);
		user.setRoles(roles);
	}

	/**
	 * 根据当前用户查询权限集合 <功能详细描述>
	 * 
	 * @param userId
	 * @param tenantId
	 * @return [参数说明]
	 * 
	 * @return List<Map<String,Object>> [返回类型说明]
	 * @exception throws
	 *                [违例类型] [违例说明]
	 * @see [类、类#方法、类#成员]
	 */
	public List<Map<String, Object>> findDataScopeListByUser(Long userId, Long tenantId) {
		return sysRoleMapper.findDataScopeListByUser(userId, tenantId);
	}

	/**
	 * 去除code为空的数据
	 * 
	 * @param roleList
	 */
	private void processRole(List<SysRole> roleList) {
		if (roleList != null && !roleList.isEmpty()) {
			for (Iterator<SysRole> iter = roleList.iterator(); iter.hasNext();) {
				if (StringUtils.isBlank(iter.next().getCode())) {
					iter.remove();
				}
			}
		}
	}

	/**
	 * 去除code为空的数据
	 * 
	 * @param menuList
	 */
	@SuppressWarnings("unused")
	private void processMenu(List<SysMenu> menuList) {
		if (menuList != null && !menuList.isEmpty()) {
			for (Iterator<SysMenu> iter = menuList.iterator(); iter.hasNext();) {
				if (StringUtils.isBlank(iter.next().getCode())) {
					iter.remove();
				}
			}
		}
	}

	/**
	 * 是否当前机构管理员
	 * 
	 * @param userId
	 *            当前登录用户的id
	 * @param tenantId
	 *            要访问的租户id
	 */
	public boolean isOrgAdmin(Long userId, Long tenantId) {
		Boolean orgAdmin = this.sysRoleMapper.isOrgAdmin(userId, tenantId);
		if (orgAdmin == null) {
			return false;
		}
		return orgAdmin;
	}

	/**
	 * 是否子机构
	 * 
	 * @param parentTenantId
	 * @param subTenantId
	 * @return
	 */
	public boolean isSubOrg(Long parentTenantId, Long subTenantId) {
		Boolean flag = this.sysRoleMapper.isSubOrg(parentTenantId, subTenantId);
		if (flag == null) {
			return false;
		}
		return flag;
	}

	/**
	 * 取当前登录用户的角色
	 * 
	 * @param userId
	 *            当前登录用户的id
	 * @param tenantId
	 *            要访问的租户id
	 */
	public void getRoleByUser(Long userId, Long tenantId) {

	}

	public void removePerms(Long roleId) {
		List<Map<String, Object>> users = this.sysUserMapper.getUsersByRole(roleId);
		if (users != null && !users.isEmpty()) {
			for (Map<String, Object> map : users) {
				String mobile = map.get("mobile").toString();
				Long tenantId = (Long) map.get("tenantId");
				this.jwtTokenUtil.delUserDetails(mobile, tenantId);
			}
		}
	}

	public List<Long> getSubTenants(String perttern) {
		return this.sysUserMapper.getSubTenantList(perttern);
	}

	public String genPwd(String pass) {
		return passwordEncoder.encode(pass);
	}

	public void updateLoginInfo(Map<String, Object> map) {
		sysUserMapper.updateLoginInfo(map);
	}

	/**
	 * 机构是否可用
	 * 
	 * @param tenantId
	 *            要访问的租户id
	 */
	public boolean isTenantEnable(Long tenantId) {
		Boolean enable = this.sysRoleMapper.isTenantEnable(tenantId);
		if (enable == null || enable == false) {
			return false;
		}
		return true;
	}

	/**
	 * 获取机构信息
	 * 
	 * @param tenantId
	 * @return
	 */
	public Map<String, Object> getTenant(Long tenantId) {
		return sysRoleMapper.getTenant(tenantId);
	}

	/**
	 * 获取机构审核信息
	 * 
	 * @param tenantId
	 * @return
	 */
	public SysTenant getTenantInfo(Long tenantId) {
		return sysRoleMapper.getTenantInfo(tenantId);
	}

	public String getRemoteIp() {
		return remoteIp;
	}

	public void setRemoteIp(String remoteIp) {
		this.remoteIp = remoteIp;
	}
	
	public WxUserVo getWxUser(Long userId,String openId){
		SysUser user = sysUserMapper.selectById(userId);	
		if(user==null)return null;
		WxUserVo wxUser = BeanMapper.map(user, WxUserVo.class);
		wxUser.setId(userId);
		wxUser.setName(user.getRealName());
		SysTenant tenant = sysRoleMapper.getTenantById(user.getTenantId());
		if(tenant!=null){
			wxUser.setTenantType(tenant.getTenantType());
			SysTenant manageTenant = sysRoleMapper.getTenantById(tenant.getManageTenantId());
			if(manageTenant!=null)wxUser.setManageTenantName(manageTenant.getName());
		};
		wxUser.setIsRcvMsg(wxSysUserMapper.getWxUserEnable(userId, openId));
		return wxUser;	
	}

}
