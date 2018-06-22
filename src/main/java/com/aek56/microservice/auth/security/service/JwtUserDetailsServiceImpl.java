package com.aek56.microservice.auth.security.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import com.aek56.microservice.auth.entity.SysUser;
import com.aek56.microservice.auth.exception.UserNotExistException;
import com.aek56.microservice.auth.model.security.AuthUserFactory;

@Service
public class JwtUserDetailsServiceImpl implements UserDetailsService {

	/**
	 * 系统服务
	 */
	@Autowired
	private SystemService systemService;

	@Override
	public UserDetails loadUserByUsername(String loginName) {
		SysUser user = systemService.getUserByLoginName(loginName);

		if (user == null) {
			throw new UserNotExistException(String.format("No user found with username '%s'.", loginName));
		}
		Map<String,Object> currentTenant = systemService.getTenant(user.getTenantId());
		
		systemService.getPerms(user, null);
		return AuthUserFactory.create(user,currentTenant);
	}
}
