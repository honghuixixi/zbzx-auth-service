package com.aek56.microservice.auth.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.aek56.microservice.auth.bo.RoleCustom;
import com.aek56.microservice.auth.bo.SysDeptBo;
import com.aek56.microservice.auth.entity.SysUser;
import com.aek56.microservice.auth.model.security.AuthUser;
import com.aek56.microservice.auth.model.security.AuthUserFactory;
import com.aek56.microservice.auth.model.security.TokenInfo;
import com.aek56.microservice.auth.redis.RedisRepository;
import com.aek56.microservice.auth.security.service.SystemService;
import com.aek56.microservice.auth.util.RequestUtils;
import com.alibaba.fastjson.JSON;
import com.google.common.collect.Lists;
import com.google.gson.Gson;

public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationTokenFilter.class);
    
    //默认机构ID值
    private static final long DEFAULT_TENANT_ID = -1L;
    
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private SystemService systemService;
    @Value("${jwt.header}")
    private String tokenHeader;
    @Value("${cookie.domain:aek.com}")
	private String cookieDomain;
	@Autowired
	private RedisRepository redisRepository;
	
	@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
    	LOGGER.debug("requestUri = "+request.getRequestURI());
		//获取token
    	String authToken = request.getHeader(this.tokenHeader);
    	if(authToken == null || StringUtils.isBlank(authToken)){  	
    		//获取cookie中token信息
    		authToken = extractAccessToken(request);
    	}
    	
    	//获取请求IP地址
    	String remoteIp = RequestUtils.getRemoteAddr(request);
    	systemService.setRemoteIp(remoteIp);
    	
    	//切换机构时目标机构ID,获取不到或异常或未传该参数值时，默认0
    	Long tenantId = RequestUtils.getParam(request, "tenantId", DEFAULT_TENANT_ID);
    	
    	//验证token是否有效
    	if (jwtTokenUtil.validateToken(authToken)) {
			String deviceId = jwtTokenUtil.getDeviceIdFromToken(authToken);
    		String username = jwtTokenUtil.getUsernameFromToken(authToken);
    		LOGGER.debug("1.current tenantId=" + tenantId);
			LOGGER.debug("2.current token=" + authToken);
			LOGGER.debug("3.current deviceId=" + deviceId);
			LOGGER.debug("4.current username=" + username);
			
    		if (StringUtils.isNotBlank(username)) {
    			if (SecurityContextHolder.getContext().getAuthentication() == null) {
    				AuthUser userDetails = null;
    				SysUser user = systemService.getUserByLoginName(username);
    				String key = deviceId + ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + username;
					String authJson = redisRepository.get(key);
					Gson gson = new Gson();
					TokenInfo tokenInfo = gson.fromJson(authJson, TokenInfo.class);
					
					//1.机构切换，更新TokenInfo中机构、数据权限、组织机构代码、机构类型
					//2.重建目标机构中当前登录用户user-detail
    				if(tenantId != DEFAULT_TENANT_ID && !tenantId.equals(tokenInfo.getTenantId())){
						//1.1 切换机构Id
						tokenInfo.setTenantId(tenantId);
						//1.2 更新数据权限
						if(null != user){
							List<Map<String,Object>> dataScopes = systemService.findDataScopeListByUser(user.getId(),tenantId);
							tokenInfo.setDataScope(jwtTokenUtil.convertDataScope(dataScopes));
						}
						//1.3 更新机构组织代码与机构类型
						Map<String,Object> currentTenant = systemService.getTenant(tenantId);
						if(null != currentTenant){
							tokenInfo.setTenantLicense(currentTenant.get("license")==null ? null:currentTenant.get("license").toString());
    						tokenInfo.setTenantType(currentTenant.get("tenant_type")==null ? null:Integer.valueOf(currentTenant.get("tenant_type").toString()));
						}
						
						Long ttl = redisRepository.ttl(key);
						redisRepository.setExpire(key, gson.toJson(tokenInfo), ttl);
						
						//2.1 重建目标机构中当前登录用户user-detail
						if(null != user){
							systemService.getPerms(user, tenantId);
	    					user.setDeviceId(deviceId);
	    					userDetails = AuthUserFactory.create(user,currentTenant);
	    					userDetails.setPassword(null);
	    					jwtTokenUtil.putUserDetails(userDetails, tenantId);
						}
    				} else {
    					//未切换机构，还是当前登录用户及其所属机构
    					String redisUserInfo = this.jwtTokenUtil.getAuthUserString(authToken, tokenInfo.getTenantId());
    					if(StringUtils.isNotBlank(redisUserInfo)){
    						userDetails = gson.fromJson(redisUserInfo, AuthUser.class);
    					}else{
    						//如果当前用户user-detail发生变化时（被清空），则重新构建当前用户user-detail
    						if(null != user){
    							Map<String,Object> currentTenant = systemService.getTenant(tokenInfo.getTenantId());
    							systemService.getPerms(user, tokenInfo.getTenantId());
    	    					user.setDeviceId(deviceId);
    	    					userDetails = AuthUserFactory.create(user,currentTenant);
    	    					userDetails.setPassword(null);
    	    					jwtTokenUtil.putUserDetails(userDetails, tokenInfo.getTenantId());
    						}
    					}
    				}
    				if(null != userDetails){
    					UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        				SecurityContextHolder.getContext().setAuthentication(authentication);
    				}
    			}
    		}
    	}else if (StringUtils.isNotBlank(authToken)){
    		//450无效token时，清除浏览器cookie token
			Cookie[] cookies = request.getCookies();
    		if(cookies!=null&&cookies.length>0){
    			for (Cookie cookie : cookies) {
					if(tokenHeader.equals(cookie.getName())){
						authToken = cookie.getValue();
						Cookie newCookie=new Cookie(tokenHeader,null); 
						newCookie.setMaxAge(0);        //立即删除型
						newCookie.setPath("/");        //项目所有目录均有效，这句很关键，否则不敢保证删除
						newCookie.setDomain(cookieDomain);
						response.addCookie(newCookie); //重新写入，将覆盖之前的
					}
				}
    		}
    		response.setContentType("application/json;charset=utf-8");
    		Map<String,String> retVal = new HashMap<>();
    		retVal.put("code", "450");
    		retVal.put("msg", "Invalid token.");
    		Gson gson = new Gson();
    		String json = gson.toJson(retVal);
    		response.getOutputStream().write(json.getBytes("UTF-8"));
    		return;
    	}
    	chain.doFilter(request, response);
    }
    
    /**
     * 获取cookie中token信息
     * @param req
     * @return
     */
    private String extractAccessToken(HttpServletRequest req) {
        final Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                if (cookies[i].getName().equalsIgnoreCase(this.tokenHeader)) {
                    return cookies[i].getValue();
                }
            }
        }
        return null;
    }
}