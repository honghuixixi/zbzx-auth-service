package com.aek56.microservice.auth.security;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mobile.device.Device;
import org.springframework.stereotype.Component;

import com.aek56.microservice.auth.bo.RoleCustom;
import com.aek56.microservice.auth.bo.SysDeptBo;
import com.aek56.microservice.auth.model.security.AuthUser;
import com.aek56.microservice.auth.model.security.TokenInfo;
import com.aek56.microservice.auth.redis.RedisRepository;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.google.common.collect.Lists;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -3301605591108950415L;

	private static final String CLAIM_KEY_AUDIENCE = "aud";

	private static final String CLAIM_KEY_CREATED = "created";

	public static final String CLAIM_KEY_DEVICE_ID = "deviceId";
	
	public static final String CLAIM_KEY_DATA_SCOPE = "dataScope";

	private static final String AUDIENCE_UNKNOWN = "unknown";

	private static final String AUDIENCE_WEB = "web";

	private static final String AUDIENCE_MOBILE = "mobile";

	private static final String AUDIENCE_TABLET = "tablet";

	/**
	 * Token 类型
	 */
	public static final String TOKEN_TYPE_BEARER = "Bearer";

	/**
	 * 权限缓存前缀
	 */
	public static final String REDIS_PREFIX_AUTH = "auth:";

	/**
	 * 用户信息缓存前缀
	 */
	public static final String REDIS_PREFIX_USER = "user-details:";
	
	/**
	 * issuer
	 */
	
	private static final String OFFICIAL_ISSUER = "aek56.com";

	/**
	 * redis repository
	 */
	@Autowired
	private RedisRepository redisRepository;	


	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private Long expiration;

	public String getUsernameFromToken(String token) {
		String username;
		try {
			final Claims claims = getClaimsFromToken(token);
			username = claims.getSubject();
		} catch (Exception e) {
			username = null;
		}
		return username;
	}

	/**
	 * 获取设备
	 *
	 * @param token
	 *            Token
	 * @return String
	 */
	public String getDeviceIdFromToken(String token) {
		Claims claims = getClaimsFromToken(token);
		return claims != null ? claims.get(CLAIM_KEY_DEVICE_ID).toString() : null;
	}
	
	/**
	 * 从token中获取权限对应的数据范围
	 * <功能详细描述>
	 * @param token
	 * @return [参数说明]
	 * 
	 * @return String [返回类型说明]
	 * @exception throws [违例类型] [违例说明]
	 * @see [类、类#方法、类#成员]
	 */
	public String getDataScopeFromToken(String token){
		Claims claims = getClaimsFromToken(token);
		return claims != null ? claims.get(CLAIM_KEY_DATA_SCOPE).toString() : null;
	}

	public Date getCreatedDateFromToken(String token) {
		Date created;
		try {
			final Claims claims = getClaimsFromToken(token);
			created = new Date((Long) claims.get(CLAIM_KEY_CREATED));
		} catch (Exception e) {
			created = null;
		}
		return created;
	}

	public Date getExpirationDateFromToken(String token) {
		Date expiration;
		try {
			final Claims claims = getClaimsFromToken(token);
			expiration = claims.getExpiration();
		} catch (Exception e) {
			expiration = null;
		}
		return expiration;
	}

	public String getAudienceFromToken(String token) {
		String audience;
		try {
			final Claims claims = getClaimsFromToken(token);
			audience = (String) claims.get(CLAIM_KEY_AUDIENCE);
		} catch (Exception e) {
			audience = null;
		}
		return audience;
	}

	public Claims getClaimsFromToken(String token) {
		Claims claims;
		try {
			claims = Jwts.parser().requireIssuer(JwtTokenUtil.OFFICIAL_ISSUER).setSigningKey(secret).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			claims = null;
		}
		return claims;
	}

	private Date generateExpirationDate() {
		return new Date(System.currentTimeMillis() + expiration * 1000);

	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		if(expiration==null){
			return false;
		}
		return expiration.before(new Date());
	}

	private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
		return (lastPasswordReset != null && created.before(lastPasswordReset));
	}

	private String generateAudience(Device device) {
		String audience = AUDIENCE_UNKNOWN;
		if (device.isNormal()) {
			audience = AUDIENCE_WEB;
		} else if (device.isTablet()) {
			audience = AUDIENCE_TABLET;
		} else if (device.isMobile()) {
			audience = AUDIENCE_MOBILE;
		}
		return audience;
	}

	private Boolean ignoreTokenExpiration(String token) {
		String audience = getAudienceFromToken(token);
		return (AUDIENCE_TABLET.equals(audience) || AUDIENCE_MOBILE.equals(audience));
	}

	/**
	 * 生成 Token
	 *
	 * @param userDetails
	 *            用户信息
	 * @return String
	 */
	public String generateToken(AuthUser userDetails, Device device, List<Map<String,Object>> dataScopes) {
		Map<String, Object> claims = new HashMap<>();
		claims.put(CLAIM_KEY_DEVICE_ID, userDetails.getDeviceId());
		
		String token = Jwts.builder().setClaims(claims).setSubject(userDetails.getLoginName()) // 统一转换手机号
				.setAudience(generateAudience(device)).setIssuer(JwtTokenUtil.OFFICIAL_ISSUER).setExpiration(generateExpirationDate())
				.signWith(SignatureAlgorithm.HS512, secret).compact();

		//统一改成手机号		
		String key = userDetails.getDeviceId() + ":" + REDIS_PREFIX_AUTH + userDetails.getLoginName();
		TokenInfo tokenInfo = new TokenInfo();
		tokenInfo.setInTenantId(userDetails.getTenantId());// 所属租户
		tokenInfo.setTenantId(userDetails.getTenantId());// 当前租户
		tokenInfo.setToken(token);
		Date now = new Date();
		tokenInfo.setLoginTime(now);
		tokenInfo.setNeedRefresh(false);
		
		//添加数据权限
    	tokenInfo.setDataScope(convertDataScope(dataScopes));
    	
    	//添加用户所属部门
    	tokenInfo.setInDeptId(userDetails.getDeptId());
    	
    	//添加租户组织结构代码
    	tokenInfo.setTenantLicense(userDetails.getTenantLicense());
    	
    	//添加租户机构类型    [1=医疗机构,2=监管机构,3=设备供应商,4=设备维修商,5=配件供应商]
    	tokenInfo.setTenantType(userDetails.getTenantType());
    	
		redisRepository.setExpire(key, new Gson().toJson(tokenInfo), expiration);
		userDetails.setPassword(null);
		putUserDetails(userDetails, userDetails.getTenantId());
		return token;
	}

	/**
	 * 验证 Token
	 *
	 * @param token
	 *            Token
	 * @return Boolean
	 */
	public Boolean validateToken(String token) {
		if (StringUtils.isBlank(token)) {
			return false;
		}
		final String username = getUsernameFromToken(token);// mobileNo
		if(StringUtils.isBlank(username)){
			return false;
		}
		final String deviceid = getDeviceIdFromToken(token);
		String key = deviceid + ":" + REDIS_PREFIX_AUTH + username;
		String redisTokenInfo = redisRepository.get(key);
		Gson gson = new Gson();
		TokenInfo tokenInfo = gson.fromJson(redisTokenInfo, TokenInfo.class);
		return !isTokenExpired(token) && tokenInfo != null && token.equals(tokenInfo.getToken());

	}

	/**
	 * 移除 Token
	 *
	 * @param token
	 *            Token
	 */
//	public void removeToken(String token) {
//		final String username = getUsernameFromToken(token);
//		final String deviceid = getDeviceIdFromToken(token);
//		String key = deviceid + ":" + REDIS_PREFIX_AUTH + username;
//		TokenInfo device = new Gson().fromJson(redisRepository.get(key), TokenInfo.class);
//		redisRepository.del(key);
//
//		// 读取当前租户的ID
//		delUserDetails(username, device.getTenantId());
//
//	}

	/**
	 * 获得用户信息 Json 字符串
	 *
	 * @param token
	 *            Token
	 * @return String
	 */
	protected String getUserDetailsString(String token) {
		final String username = getUsernameFromToken(token);
		final String deviceid = getDeviceIdFromToken(token);
		String key = deviceid + ":" + REDIS_PREFIX_USER + username;
		return redisRepository.get(key);
	}

	/**
	 * 获得用户信息 Json 字符串
	 *
	 * @param token
	 *            Token
	 * @param tenantId
	 *            跨租户时需要传入要访问的tenantId，返回当前租户的user-detail
	 * @return String
	 */
	public String getAuthUserString(String token, Long tenantId) {
		
		final String username = getUsernameFromToken(token);
		
		if (tenantId == null || tenantId < 1) {//返回当前租户			
			final String deviceid = getDeviceIdFromToken(token);
			String key = deviceid + ":" + REDIS_PREFIX_AUTH + username;
			TokenInfo tokenInfo = new Gson().fromJson(redisRepository.get(key), TokenInfo.class);
			
			tenantId = tokenInfo.getTenantId();
		}
		String keyUserDetail = tenantId + ":" + REDIS_PREFIX_USER + username;
		return redisRepository.get(keyUserDetail);
	}

	/**
	 * 存储用户信息
	 *
	 * @param userDetails
	 *            用户信息
	 */
	public void putUserDetails(AuthUser userDetails, Long tenantId) {
		if (tenantId == null || tenantId < 1) {
			tenantId = userDetails.getTenantId();
		}
		//更新为登录名
		String key = tenantId + ":" + REDIS_PREFIX_USER + userDetails.getLoginName();

		redisRepository.setExpire(key, new Gson().toJson(userDetails), expiration);
	}

	/**
	 * 删除用户信息
	 *
	 * @param username
	 *            用户名
	 */
	public void delUserDetails(String username, Long tenantId) {
		String key = tenantId + ":" + REDIS_PREFIX_USER + username;
		redisRepository.del(key);
	}

	public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
		final Date created = getCreatedDateFromToken(token);
		return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
				&& (!isTokenExpired(token) || ignoreTokenExpiration(token));
	}
	
	/**
	 * 转换数据权限数据，组装为{{"SYS_USER_MANAGE":1,"definedDeptIds":[1,2,3]},{"SYS_USER_MANAGE":1,"definedDeptIds":[1,2,3]}}
	 * @param dataScopes
	 * @return
	 */
	public List<Map<String, Object>> convertDataScope(List<Map<String,Object>> dataScopes){
		List<Map<String,Object>> dataScopeMapList = new ArrayList<Map<String,Object>>();
    	for (Map<String, Object> dataScope : dataScopes) {
    		if(null != dataScope && null != dataScope.get("code") && null != dataScope.get("data_scope")){
    			Map<String, Object> dataScopeMap = new HashMap<>();
    			String codeValue = dataScope.get("code").toString();
    			Integer dataScopeValue = (Integer)dataScope.get("data_scope");
    			dataScopeMap.put(codeValue, dataScopeValue);
    			if(null != dataScope.get("custom_data")){
    				String customData = (String)dataScope.get("custom_data");
        			RoleCustom roleCustom = JSON.parseObject(customData, RoleCustom.class);
        			if(null != roleCustom){
        				List<SysDeptBo> sysDepts = roleCustom.getDepts();
        				List<Long> deptIds = Lists.newArrayList();
        				for (SysDeptBo sysDeptBo : sysDepts) {
        					deptIds.add(sysDeptBo.getDeptId());
    					}
        				dataScopeMap.put("definedDeptIds", deptIds);
        			}
    			}
    			dataScopeMapList.add(dataScopeMap);
    		}
		}
    	return dataScopeMapList;
	}

	public Long getExpiration() {
		return expiration;
	}

	public void setExpiration(Long expiration) {
		this.expiration = expiration;
	}

}