
package com.aek56.microservice.auth.apis;

import java.nio.charset.Charset;
import java.security.Principal;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.mobile.device.Device;
import org.springframework.mobile.device.DevicePlatform;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestOperations;

import com.aek56.microservice.auth.bo.VerifyCode;
import com.aek56.microservice.auth.config.SmsConfig;
import com.aek56.microservice.auth.entity.SysTenant;
import com.aek56.microservice.auth.entity.SysUser;
import com.aek56.microservice.auth.entity.WxSysUser;
import com.aek56.microservice.auth.entity.WxUserVo;
import com.aek56.microservice.auth.enums.LoginType;
import com.aek56.microservice.auth.model.security.AuthUser;
import com.aek56.microservice.auth.model.security.SmsResult;
import com.aek56.microservice.auth.model.security.TokenInfo;
import com.aek56.microservice.auth.redis.RedisRepository;
import com.aek56.microservice.auth.security.JwtAuthenticationRequest;
import com.aek56.microservice.auth.security.JwtTokenUtil;
import com.aek56.microservice.auth.security.service.SystemService;
import com.aek56.microservice.auth.util.RegexValidateUtil;
import com.aek56.microservice.auth.util.SecurityUtil;
import com.aek56.microservice.auth.util.ThreadHolder;
import com.aek56.microservice.auth.weixin.WxSysUserService;
import com.alibaba.fastjson.JSON;
import com.google.gson.Gson;

import io.jsonwebtoken.Claims;

@RestController
public class AuthController {
	private static final Log logger = LogFactory.getLog(AuthController.class);

	@Value("${jwt.header}")
	private String tokenHeader;
	@Value("${cookie.domain:aek.com}")
	private String cookieDomain;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private SystemService systemService;
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	@Autowired
	private RedisRepository redisRepository;
	@Autowired
	private RestOperations restOperations;
	@Autowired
	private SmsConfig config;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private WxSysUserService wxSysUserService;

	/**
	 * PC端管理平台登录接口
	 */
	@PostMapping(value = "/authByLoginName")
	public Map<String, Object> createAuthenticationTokenByLoginName(@RequestBody JwtAuthenticationRequest request, Device device,
			HttpServletResponse response) {
		logger.debug(device);
		String deviceId = request.getDeviceId();
		Map<String, Object> map = new HashMap<String, Object>();
		if (deviceId == null || deviceId.length() < 10) {// 终端编号不能小于10
			map.put("code", 401);
			map.put("msg", "设备ID不能少于10位.");
			return map;
		}
		// 用户名或密码不正确
		String username = request.getUsername();
		String password = request.getPassword();

		if (username == null || username.isEmpty()){
			map.put("code", 403);
			map.put("msg", "请输入用户名");
			return map;
		} 
		
		//只支持登录名，不支持邮箱和手机号
		SysUser user = systemService.getUserInfoByLoginName(username);
		if (null == user) {
			map.put("code", "411");
			map.put("msg", "用户名不正确");
			return map;
		}
		
		//1.短信验证码登录
		if(null != request.getLoginType() && LoginType.VALIDATE_CODE_LOGIN.getNumber().equals(request.getLoginType())){
			if( password == null || password.isEmpty()) {
				map.put("code", 403);
				map.put("msg", "请输入验证码");
				return map;
			}
			String smsLoginPwdKey = deviceId + ":loginPwd:" + user.getMobile();
			if (redisRepository.exists(smsLoginPwdKey)) {
				String smsLoginPassword = redisRepository.get(smsLoginPwdKey);
				if(StringUtils.isNotBlank(smsLoginPassword)){
					VerifyCode currVerifyCode = JSON.parseObject(smsLoginPassword, VerifyCode.class);
					if (!password.equals(currVerifyCode.getCode())) {
						map.put("code", 411);
						map.put("msg", "验证码错误或失效");
						return map;
					}
				}
			}else{
				map.put("code", 411);
				map.put("msg", "验证码错误或失效");
				return map;
			}
		}else{  
		//2.密码登录方式
			if( password == null || password.isEmpty()) {
				map.put("code", 403);
				map.put("msg", "请输入密码");
				return map;
			}
			if (!passwordEncoder.matches(password, user.getPassword())) {
				map.put("code", "411");
				map.put("msg", "用户密码不正确");
				return map;
			}
		}

		// 帐户已经被禁用
		if (user.getEnable() == false) {
			map.put("code", "413");
			map.put("msg", "此帐户已被禁用");
			return map;
		}
		
		// 机构未审核或申请被拒绝
		SysTenant sysTenant = systemService.getTenantInfo(user.getTenantId());
		if(null != sysTenant && sysTenant.getAuditStatus() == 1){
			map.put("code", "414");
			map.put("msg", "您的申请正在审核中");
			return map;
		}
		if(null != sysTenant && sysTenant.getAuditStatus() == 4){
			map.put("code", "414");
			map.put("msg", "您的申请被拒绝");
			return map;
		}

		// 机构被禁用
		if (!systemService.isTenantEnable(user.getTenantId())) {
			map.put("code", "414");
			map.put("msg", "机构已经被停用");
			return map;
		}

		String key = deviceId + ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + user.getMobile();// request.getUsername();
		String authJson = redisRepository.get(key);
		if (StringUtils.isNotBlank(authJson)) {
			Gson gson = new Gson();
			TokenInfo tokenInfo = gson.fromJson(authJson, TokenInfo.class);
			map.put("code", 402);
			map.put("tokenKey", tokenHeader);
			map.put("token", tokenInfo.getToken());
			map.put("msg", "已登录.");
			// set accessToken cookie
			final Cookie cookie = new Cookie(tokenHeader, tokenInfo.getToken());
			cookie.setHttpOnly(true);
			cookie.setMaxAge(jwtTokenUtil.getExpiration().intValue());
			cookie.setDomain(cookieDomain);
			cookie.setPath("/");
			response.addCookie(cookie);
			return map;
		}
		ThreadHolder.set(request.getDeviceId());
		// Perform the security
		final Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		AuthUser userDetails = (AuthUser) authentication.getPrincipal();
		userDetails.setDeviceId(deviceId);
		userDetails.setDeptId(user.getDeptId());

		// 更新 登陆信息
		Map<String, Object> loginInfo = new HashMap<>();
		String ip = "UNKOWN";
		ip = systemService.getRemoteIp();
		loginInfo.put("id", user.getId());
		loginInfo.put("ip", ip);
		Calendar cal = Calendar.getInstance();
		loginInfo.put("loginTime", cal.getTime());

		String device_type = "UNKOWN";
		if (device.getDevicePlatform() == DevicePlatform.IOS)
			device_type = "IOS";
		else if (device.getDevicePlatform() == DevicePlatform.ANDROID)
			device_type = "ANDROID";
		else {
			device_type = "PC";
		}
		loginInfo.put("device", device_type);
		systemService.updateLoginInfo(loginInfo);

		// 获取权限，数据范围
		List<Map<String, Object>> dataScopes = systemService.findDataScopeListByUser(user.getId(), user.getTenantId());

		final String token = jwtTokenUtil.generateToken(userDetails, device, dataScopes);
		Map<String, Object> tokenMap = new HashMap<>();
		tokenMap.put("token", token);
		cal.add(Calendar.SECOND, jwtTokenUtil.getExpiration().intValue());
		tokenMap.put("expire", cal.getTime());
		tokenMap.put("token_type", "Bearer");
		tokenMap.put("code", 200);

		// set access_token cookie
		final Cookie cookie = new Cookie(tokenHeader, token);
		cookie.setHttpOnly(true);
		cookie.setMaxAge(jwtTokenUtil.getExpiration().intValue());
		cookie.setDomain(cookieDomain);
		cookie.setPath("/");
		response.addCookie(cookie);

		return tokenMap;
	}
	
	/**
	 * 装备中心公众号登录接口，具有绑定微信用户功能
	 */
	@PostMapping(value = "/auth4WechatOfficialAccounts")
	public Map<String, Object> createAuthenticationTokenWechatOfficialAccounts(@RequestBody JwtAuthenticationRequest request, Device device,
			HttpServletResponse response) {
		logger.debug(device);
		String deviceId = request.getDeviceId();
		Map<String, Object> map = new HashMap<String, Object>();
		if (deviceId == null || deviceId.length() < 10) {// 终端编号不能小于10
			map.put("code", 401);
			map.put("msg", "设备ID不能少于10位.");
			return map;
		}
		// 用户名或密码不正确
		String username = request.getUsername();
		String password = request.getPassword();
		// 微信用户openId
		String openId = request.getOpenId();
		if(StringUtils.isNotBlank(openId)){
			//解密
			//openId = SecurityUtil.decryptDes(openId);
			try{
				openId = new String(SecurityUtil.decryptBASE64(openId),Charset.forName("UTF-8"));
			}catch(RuntimeException e){
				e.printStackTrace();
				map.put("code", 401);
				map.put("msg", "openId解密错误.");
				return map;
			}
		}else{
			map.put("code", 401);
			map.put("msg", "openId不能为空.");
			return map;
		}

		if (username == null || username.isEmpty()){
			map.put("code", 403);
			map.put("msg", "请输入用户名");
			return map;
		} 
		
		//为装备中心提供补充登录名(不支持邮箱和手机号)
		SysUser user = systemService.getUserInfoByLoginName(username);
		if (null == user) {
			map.put("code", "411");
			map.put("msg", "用户名不正确");
			return map;
		}
		
		//1.短信验证码登录
		if(null != request.getLoginType() && LoginType.VALIDATE_CODE_LOGIN.getNumber().equals(request.getLoginType())){
			if( password == null || password.isEmpty()) {
				map.put("code", 403);
				map.put("msg", "请输入验证码");
				return map;
			}
			String smsLoginPwdKey = deviceId + ":loginPwd:" + user.getMobile();
			if (redisRepository.exists(smsLoginPwdKey)) {
				String smsLoginPassword = redisRepository.get(smsLoginPwdKey);
				if(StringUtils.isNotBlank(smsLoginPassword)){
					VerifyCode currVerifyCode = JSON.parseObject(smsLoginPassword, VerifyCode.class);
					if (!password.equals(currVerifyCode.getCode())) {
						map.put("code", 411);
						map.put("msg", "验证码错误或失效");
						return map;
					}
				}
			}else{
				map.put("code", 411);
				map.put("msg", "验证码错误或失效");
				return map;
			}
		}else{  
		//2.密码登录方式
			if( password == null || password.isEmpty()) {
				map.put("code", 403);
				map.put("msg", "请输入密码");
				return map;
			}
			if (!passwordEncoder.matches(password, user.getPassword())) {
				map.put("code", "411");
				map.put("msg", "用户密码不正确");
				return map;
			}
		}

		// 帐户已经被禁用
		if (user.getEnable() == false) {
			map.put("code", "413");
			map.put("msg", "此帐户已被禁用");
			return map;
		}
		
		// 机构未审核或申请被拒绝
		SysTenant sysTenant = systemService.getTenantInfo(user.getTenantId());
		if(null != sysTenant && sysTenant.getAuditStatus() == 1){
			map.put("code", "414");
			map.put("msg", "您的申请正在审核中");
			return map;
		}
		if(null != sysTenant && sysTenant.getAuditStatus() == 4){
			map.put("code", "414");
			map.put("msg", "您的申请被拒绝");
			return map;
		}

		// 机构被禁用
		if (!systemService.isTenantEnable(user.getTenantId())) {
			map.put("code", "414");
			map.put("msg", "机构已经被停用");
			return map;
		}

		String key = deviceId + ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + user.getMobile();// request.getUsername();
		String authJson = redisRepository.get(key);
		if (StringUtils.isNotBlank(authJson)) {
			Gson gson = new Gson();
			TokenInfo tokenInfo = gson.fromJson(authJson, TokenInfo.class);
			map.put("code", 402);
			map.put("tokenKey", tokenHeader);
			map.put("token", tokenInfo.getToken());
			map.put("msg", "已登录.");
			// set accessToken cookie
			final Cookie cookie = new Cookie(tokenHeader, tokenInfo.getToken());
			cookie.setHttpOnly(true);
			cookie.setMaxAge(jwtTokenUtil.getExpiration().intValue());
			cookie.setDomain(cookieDomain);
			cookie.setPath("/");
			response.addCookie(cookie);
			return map;
		}
		ThreadHolder.set(request.getDeviceId());
		// Perform the security
		final Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		AuthUser userDetails = (AuthUser) authentication.getPrincipal();
		userDetails.setDeviceId(deviceId);
		userDetails.setDeptId(user.getDeptId());

		// 更新 登陆信息
		Map<String, Object> loginInfo = new HashMap<>();
		String ip = "UNKOWN";
		ip = systemService.getRemoteIp();
		loginInfo.put("id", user.getId());
		loginInfo.put("ip", ip);
		Calendar cal = Calendar.getInstance();
		loginInfo.put("loginTime", cal.getTime());

		String device_type = "UNKOWN";
		if (device.getDevicePlatform() == DevicePlatform.IOS)
			device_type = "IOS";
		else if (device.getDevicePlatform() == DevicePlatform.ANDROID)
			device_type = "ANDROID";
		else {
			device_type = "PC";
		}
		loginInfo.put("device", device_type);
		systemService.updateLoginInfo(loginInfo);

		// 获取权限，数据范围
		List<Map<String, Object>> dataScopes = systemService.findDataScopeListByUser(user.getId(), user.getTenantId());
		

		final String token = jwtTokenUtil.generateToken(userDetails, device, dataScopes);
		Map<String, Object> tokenMap = new HashMap<>();
		tokenMap.put("token", token);
		cal.add(Calendar.SECOND, jwtTokenUtil.getExpiration().intValue());
		tokenMap.put("expire", cal.getTime());
		tokenMap.put("token_type", "Bearer");
		tokenMap.put("code", 200);

		// set access_token cookie
		final Cookie cookie = new Cookie(tokenHeader, token);
		cookie.setHttpOnly(true);
		cookie.setMaxAge(jwtTokenUtil.getExpiration().intValue());
		cookie.setDomain(cookieDomain);
		cookie.setPath("/");
		response.addCookie(cookie);
		
		// 处理微信用户与当前登录用户绑定逻辑
		List<WxSysUser> wxSysUserList = wxSysUserService.getWxSysUserList(user.getId());
		if(null == wxSysUserList || (null != wxSysUserList && wxSysUserList.size() == 0)){
			WxSysUser sysUser = new WxSysUser();
			sysUser.setOpenId(openId);
			sysUser.setUserId(user.getId());
			sysUser.setPassword(SecurityUtil.encryptDes(password));
			// 启用
			sysUser.setEnable(true);
			wxSysUserService.saveWxSysUser(sysUser);
		}else{
			boolean existOpenId = false;
			for (WxSysUser wxSysUser : wxSysUserList) {
				if(null != wxSysUser && StringUtils.isNotBlank(openId) && StringUtils.isNotBlank(wxSysUser.getOpenId())){
					if(openId.equals(wxSysUser.getOpenId())){
						existOpenId = true;
						break;
					}
				}
			}
			if(!existOpenId){
				WxSysUser sysUser = new WxSysUser();
				sysUser.setOpenId(openId);
				sysUser.setUserId(user.getId());
				sysUser.setPassword(SecurityUtil.encryptDes(password));
				// 不启用
				sysUser.setEnable(false);
				wxSysUserService.saveWxSysUser(sysUser);
			}
		}
		
		//微信用户根据用户id和openid获取用户信息
		WxUserVo wxUser = systemService.getWxUser(user.getId(), openId);
		tokenMap.put("wxUser", wxUser);
		
		return tokenMap;
	}
	
	@PostMapping("/cache/permission/list")
	@PreAuthorize("isAuthenticated()")
	public AuthUser getPerms() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		AuthUser userDetail = (AuthUser) authentication.getPrincipal();
		userDetail.setPassword(null);
		Gson gson = new Gson();
		logger.debug(gson.toJson(userDetail));

		refreshed(userDetail.getDeviceId() + ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + userDetail.getMobile());

		return userDetail;
	}

	@RequestMapping(value = "/admin", method = RequestMethod.GET)
	// @PreAuthorize("hasRole('ADMIN')")
	// @PreAuthorize("hasIpAddress('127.0.0.1')")
	public ResponseEntity<?> getProtectedGreeting() {
		return ResponseEntity.ok("只有admin可以访问的资源");
	}

	/*
	 * @PreAuthorize("#contact.name == authentication.name") public void
	 * doSomething(Contact contact);
	 */

	@RequestMapping("/me")
	public Principal getCurrentLoggedInUser(Principal user) {
		return user;
	}

	/**
	 * 根据角色清空用户详情缓存
	 * 
	 * @param roleId
	 * @return
	 */
	@PostMapping("/cache/permission/delbyrole/{roleId}")
	@PreAuthorize("isAuthenticated()")
	public Map<String, Object> removePerms(@PathVariable(value = "roleId", required = true) Long roleId) {
		logger.debug(roleId);
		Map<String, Object> map = new HashMap<>();
		systemService.removePerms(roleId);
		map.put("code", 200);
		return map;
	}

	/**
	 * 根据手机号清空用户详情缓存
	 * 
	 * @param mobile
	 * @return
	 */
	@PostMapping(value = "/cache/permission/delbymobile/{mobile}")
	// @PreAuthorize("hasAuthority('SYS_USER_MANAGE')")
	// @PreAuthorize("isAuthenticated()")
	public Map<String, Object> removePerms(@PathVariable(value = "mobile", required = true) String mobile) {
		logger.debug(mobile);

		// 清除缓存，并且在所有的auth缓存里的needRefresh置为true
		String suffix = ":" + JwtTokenUtil.REDIS_PREFIX_USER + mobile;
		redisRepository.deleteBySuffix(suffix);
		if (!redisRepository.keys("*" + suffix).isEmpty()) {
			logger.error("removePerms error.prefix=[" + suffix + "]");
		}

		enableRefresh(mobile);

		Map<String, Object> map = new HashMap<>();
		map.put("code", 200);
		return map;
	}

	/**
	 * 机构模块发生变化清空当前租户及其子租户的用户缓存
	 * 
	 * @param tenantId
	 * @return
	 */
	@PostMapping("/cache/module/mod/{tenantId}")
	// @PreAuthorize("hasAuthority('SYS_TENANT_MANAGE')")
	public Map<String, Object> clearUserDetailByTenant(
			@PathVariable(value = "tenantId", required = true) Long tenantId) {
		logger.debug(tenantId);
		String prex = tenantId + ":" + JwtTokenUtil.REDIS_PREFIX_USER;

		Set<String> keys = redisRepository.keys(prex + "*");

		for (String key : keys) {

			String mobile = key.substring(key.lastIndexOf(":") + 1);

			enableRefresh(mobile);
		}

		redisRepository.deleteByPrex(prex);
		if (!redisRepository.keys(prex + "*").isEmpty()) {
			logger.error("clearUserDetailByTenant error.prefix=[" + prex + "]");
		}

		// 当前租户的子租户
		List<Long> subTenants = systemService.getSubTenants("%" + tenantId + "%");

		for (Long tenant : subTenants) {
			String prefix = tenant.toString() + ":" + JwtTokenUtil.REDIS_PREFIX_USER;
			Set<String> keys11 = redisRepository.keys(prefix + "*");

			for (String key : keys11) {

				String mobile = key.substring(key.lastIndexOf(":") + 1);

				enableRefresh(mobile);
			}

			redisRepository.deleteByPrex(prefix);
			if (!redisRepository.keys(prefix + "*").isEmpty()) {
				logger.error("clearUserDetailByTenant error.prefix=[" + prefix + "]");
			}

		}
		Map<String, Object> map = new HashMap<>();
		map.put("code", 200);
		return map;
	}

	/**
	 * 机构被停用，踢出该租户及子租户下的所有用户
	 * 
	 * @param tenantId
	 * @return
	 */
	@PostMapping("/cache/user/delbytenant/{tenantId}")
	// @PreAuthorize("hasAuthority('SYS_TENANT_MANAGE')")
	public Map<String, Object> clearUserByTenant(@PathVariable(value = "tenantId", required = true) Long tenantId) {
		logger.debug(tenantId);
		String prex = tenantId + ":" + JwtTokenUtil.REDIS_PREFIX_USER;
		String keyPattern = prex + "*";

		Set<String> keys = redisRepository.keys(keyPattern);
		for (String str : keys) {
			String mobile = str.substring(str.lastIndexOf(":") + 1);
			String suffix = ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + mobile;
			redisRepository.deleteBySuffix(suffix);

			if (!redisRepository.keys("*" + suffix).isEmpty()) {
				logger.error("clearUserByTenant error.suffix=[" + suffix + "]");
			}
		}
		redisRepository.deleteByPrex(prex);

		if (!redisRepository.keys(prex + "*").isEmpty()) {
			logger.error("clearUserByTenant error. prefix=[" + prex + "]");
		}

		// 当前租户的子租户

		// 当前租户的子租户
		List<Long> subTenants = systemService.getSubTenants("%" + tenantId + "%");

		keys.clear();

		for (Long tenant : subTenants) {// 处理每个租户

			String prefix = tenant.toString() + ":" + JwtTokenUtil.REDIS_PREFIX_USER;
			keys = redisRepository.keys(prefix + "*");

			for (String str : keys) {// 踢出每个子租户下的用户

				String mobile = str.substring(str.lastIndexOf(":") + 1);
				String suffix = ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + mobile;
				redisRepository.deleteBySuffix(suffix);

				if (!redisRepository.keys("*" + suffix).isEmpty()) {
					logger.error("clearUserByTenant error.suffix=[" + suffix + "]");
				}

			}
			redisRepository.deleteByPrex(prefix);
			if (!redisRepository.keys(prefix + "*").isEmpty()) {
				logger.error("clearUserDetailByTenant error.prefix=[" + prefix + "]");
			}

		}

		Map<String, Object> map = new HashMap<>();
		map.put("code", 200);
		return map;
	}

	/**
	 * 根据手机号踢出用户
	 * 
	 * @param mobile
	 * @return
	 */
	@PostMapping("/cache/user/delbymobile/{mobile}")
	// @PreAuthorize("hasAuthority('SYS_USER_MANAGE')")
	// @PreAuthorize("hasIpAddress('127.0.0.1')")
	// @PreAuthorize("isAuthenticated()")
	public Map<String, Object> removeUser(@PathVariable(value = "mobile", required = true) String mobile) {
		logger.debug(mobile);
		Map<String, Object> map = new HashMap<>();

		String suffix1 = ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + mobile;

		redisRepository.deleteBySuffix(suffix1);
		String suffix = ":" + JwtTokenUtil.REDIS_PREFIX_USER + mobile;
		redisRepository.deleteBySuffix(suffix);

		if (!redisRepository.keys("*" + suffix1).isEmpty()) {
			logger.error("removeUser error.suffix=[" + suffix1 + "]");
		}

		if (!redisRepository.keys("*" + suffix).isEmpty()) {
			logger.error("removeUser error.suffix=[" + suffix + "]");
		}

		map.put("code", 200);

		return map;
	}

	@PostMapping("/logout-success")
	@PreAuthorize("isAuthenticated()")
	public Map<String, Object> logout(@RequestHeader(value = "${jwt.header}") String token,HttpServletRequest request,HttpServletResponse response) {
		logger.debug(token);
		Map<String, Object> map = new HashMap<>();
		Claims claims = jwtTokenUtil.getClaimsFromToken(token);

		String username = claims.getSubject();
		String deviceId = claims.get(JwtTokenUtil.CLAIM_KEY_DEVICE_ID).toString();

		String authKey = deviceId + ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + username;

		String authJson = redisRepository.get(authKey);
		Gson gson = new Gson();

		TokenInfo tokenInfo = gson.fromJson(authJson, TokenInfo.class);
		Long tenantId = tokenInfo.getTenantId();// 获取当前的 租户id

		redisRepository.del(authKey);
		if (redisRepository.exists(authKey)) {
			logger.error("logout error. authKey=[" + authKey + "]");
		}
		// 判断该用户还有无其他有效token,如果没有了，则删除其user-detail缓存。如果还有token，就只删除与这个登出的token
		// 关联的user-detail缓存，否则,删除该用户所有的user-detail，其他token再访问资源时，就会返回302的错误
		String keyuserdetail = tenantId.toString() + ":" + JwtTokenUtil.REDIS_PREFIX_USER + username;
		redisRepository.del(keyuserdetail);

		// 如果用户已经没有了auth 的缓存，则清理该用户所有的 user-detail缓存
		String suffix = ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + username;
		if (redisRepository.keys("*" + suffix).isEmpty()) {
			suffix = ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + username;
			redisRepository.deleteBySuffix(suffix);
			if (!redisRepository.keys("*" + suffix).isEmpty()) {
				logger.error("logout error.suffix=[" + suffix + "]");
			}
		}

		//清除浏览器cookie token
		Cookie[] cookies = request.getCookies();
		if(cookies!=null&&cookies.length>0){
			for (Cookie cookie : cookies) {
				if(tokenHeader.equals(cookie.getName())){
					Cookie newCookie=new Cookie(tokenHeader,null); 
					newCookie.setMaxAge(0);        //立即删除型
					newCookie.setPath("/");        //项目所有目录均有效，这句很关键，否则不敢保证删除
					newCookie.setDomain(cookieDomain);
					response.addCookie(newCookie); //重新写入，将覆盖之前的
				}
			}
		}
		
		map.put("code", 200);
		map.put("msg", "退出成功.");
		return map;
	}

	/**
	 * 发送短信密码
	 * 
	 * @return
	 */
	@PostMapping("/sendLoginPwd")
	public Map<String, Object> sendLoginPwd(@RequestParam(required = true) String mobile,
			@RequestParam(required = true) String deviceId,
			@RequestHeader(value = "${jwt.header}", required = false) String token) {
		logger.debug(mobile + ", " + deviceId + ", " + token);
		Map<String, Object> map = new HashMap<>();
		if (StringUtils.isBlank(mobile) || !RegexValidateUtil.checkCellphone(mobile.trim())) {
			map.put("code", 407);
			map.put("msg", "手机号不正确");
			return map;
		}
		if (StringUtils.isBlank(deviceId) || deviceId.length() < 10) {
			map.put("code", 408);
			map.put("msg", "设备ID不能少于10位");
			return map;
		}
		SysUser user = systemService.getUserByMobile(mobile.trim());
		if (user == null) {
			map.put("code", 409);
			map.put("msg", "该用户不存在");
			return map;
		}else if(!user.getEnable()){
			map.put("code", 409);
			map.put("msg", "此帐户已被禁用");
			return map;
		}
		
		//短信登录，验证码存入缓存key
		String smsCodeKey = deviceId + ":loginPwd:" + mobile.trim();
		
		//查询是否在1分钟内发送过验证码，则不发送返回1分钟重试
		Date currTime = new Date();
		String verifyCodeJson = this.redisRepository.get(smsCodeKey);
		if (StringUtils.isNotBlank(verifyCodeJson)) {
			VerifyCode currVerifyCode = JSON.parseObject(verifyCodeJson, VerifyCode.class);
			long date = currTime.getTime() - currVerifyCode.getSendTime().getTime();
			if ((date / 60000) < 1) {
				map.put("code", 411);
				map.put("msg", "验证码已发送至您手机，请60s后重试");
				return map;
			}
		}

		if (StringUtils.isNotBlank(token)) {
			Claims claims = jwtTokenUtil.getClaimsFromToken(token);
			String username = claims.getSubject();
			String tokenDeviceId = claims.get(JwtTokenUtil.CLAIM_KEY_DEVICE_ID).toString();
			String authKey = tokenDeviceId + ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + username;
			if (redisRepository.exists(authKey)) {
				map.put("code", 402);
				map.put("msg", "已登录");
				return map;
			}
		}
		String pwd = this.genPwd(6);
		SmsResult sendMsg = this.sendMsg(mobile, pwd, 30, this.config.getLoginTpl());
		logger.debug(JSON.toJSONString(sendMsg));
		if(null != sendMsg){
			if(sendMsg.getSuccess() == 1){
				// 过期时间 30分钟
				long expireTime = 30 * 60;
				VerifyCode verifyCode = new VerifyCode();
				verifyCode.setCode(pwd);
				verifyCode.setSendTime(new Date());
				// 保存验证码
				String value = JSON.toJSONString(verifyCode);
				redisRepository.setExpire(smsCodeKey, value, expireTime);
				
				map.put("code", 200);
				map.put("msg", "密码发送成功");
			}else if(null != sendMsg.getErrcode() && sendMsg.getErrcode() == 32){
				map.put("code", 410);
				map.put("msg", "同一手机号一天中短信只能发送6次");
			}else{
				map.put("code", 410);
				map.put("msg", sendMsg.getMsg());
			}
		}else{
			map.put("code", 410);
			map.put("msg", "密码发送失败");
		}
		return map;
	}

	/**
	 * 生成i位随机密码
	 * 
	 * @param n
	 * @return
	 */
	private String genPwd(int n) {
		Random random = new Random();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < n; i++) {
			sb.append(random.nextInt(10));
		}
		return sb.toString();
	}

	/**
	 * 发送短信
	 * 
	 * @param mobile
	 * @param code
	 * @param expire
	 * @return
	 */
	private SmsResult sendMsg(String mobile, String code, Integer expire, int tpl) {
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("usr", config.getUsr());
		params.put("psw", config.getPsw());
		params.put("authkey", config.getAuthkey());
		params.put("mobile", mobile);
		params.put("tpl", tpl);

		// 模板不同参数不同
		if (tpl == config.getLoginTpl()) {
			params.put("text[vPass]", code);
			params.put("text[vExpire]", expire);

		} else if (tpl == config.getCodeTpl()) {
			params.put("text[vCode]", code);
		}

		// url 参数处理
		String url = this.urlDispose(config.getUrl(), params);
		String result = this.restOperations.getForObject(url, String.class, params);
		return JSON.parseObject(result, SmsResult.class);
	}

	/**
	 * url处理
	 * 
	 * @param url
	 * @param params
	 * @return
	 */
	private String urlDispose(String url, Map<String, Object> params) {
		StringBuilder builder = new StringBuilder(url);
		builder.append("?");
		Set<String> paramKey = params.keySet();
		for (String key : paramKey) {
			builder.append(key).append("=").append("{").append(key).append("}").append("&");
		}
		return builder.toString();
	}

	/**
	 * 一个帐户有多台终端登录,权限发生变化时，其他终端也需要重新获取权限
	 * @param mobile
	 */
	private void enableRefresh(String mobile) {
		String suffix = ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + mobile;
		Set<String> keys = redisRepository.keys("*" + suffix);
		// 更新auth缓存的needRefresh标记
		for (String key : keys) {
			String authJson = redisRepository.get(key);
			Gson gson = new Gson();
			TokenInfo tokenInfo = gson.fromJson(authJson, TokenInfo.class);
			if (tokenInfo != null) {
				tokenInfo.setNeedRefresh(true);
				Long ttl = redisRepository.ttl(key);
				redisRepository.setExpire(key, gson.toJson(tokenInfo), ttl);
			}
		}
	}

	// 更新auth缓存的needRefresh标记
	private void refreshed(String key) { 
		String authJson = redisRepository.get(key);
		Gson gson = new Gson();
		TokenInfo tokenInfo = gson.fromJson(authJson, TokenInfo.class);
		if (tokenInfo != null) {
			tokenInfo.setNeedRefresh(false);
			Long ttl = redisRepository.ttl(key);
			redisRepository.setExpire(key, gson.toJson(tokenInfo), ttl);
		}
	}
}
