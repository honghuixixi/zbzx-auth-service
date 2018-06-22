package com.aek56.microservice.auth.apis;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mobile.device.Device;
import org.springframework.mobile.device.DevicePlatform;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.aek56.microservice.auth.apis.ribbon.FileServerClientService;
import com.aek56.microservice.auth.bo.FileItem;
import com.aek56.microservice.auth.bo.UploadInfo;
import com.aek56.microservice.auth.common.BaseController;
import com.aek56.microservice.auth.common.Result;
import com.aek56.microservice.auth.entity.SysTenant;
import com.aek56.microservice.auth.entity.SysUser;
import com.aek56.microservice.auth.entity.WxSysUser;
import com.aek56.microservice.auth.enums.TenantType;
import com.aek56.microservice.auth.exception.BusinessException;
import com.aek56.microservice.auth.exception.ExceptionFactory;
import com.aek56.microservice.auth.model.security.AuthUser;
import com.aek56.microservice.auth.model.security.TokenInfo;
import com.aek56.microservice.auth.redis.RedisRepository;
import com.aek56.microservice.auth.security.JwtTokenUtil;
import com.aek56.microservice.auth.security.service.SystemService;
import com.aek56.microservice.auth.util.MapUtils;
import com.aek56.microservice.auth.util.SecurityUtil;
import com.aek56.microservice.auth.util.ThreadHolder;
import com.aek56.microservice.auth.weixin.SysUserService;
import com.aek56.microservice.auth.weixin.WeiXinConstants;
import com.aek56.microservice.auth.weixin.WeiXinService;
import com.aek56.microservice.auth.weixin.WeiXinSignUtil;
import com.aek56.microservice.auth.weixin.WeiXinUtil;
import com.aek56.microservice.auth.weixin.WxSysUserService;
import com.aek56.microservice.auth.weixin.config.WeiXinConfig;
import com.aek56.microservice.auth.weixin.enums.WeiXinScopeEnum;
import com.aek56.microservice.auth.weixin.message.template.TemplateMsgResult;
import com.aek56.microservice.auth.weixin.message.template.WeiXinRepairTemplate;
import com.aek56.microservice.auth.weixin.message.template.WeiXinServiceTemplate;
import com.aek56.microservice.auth.weixin.request.WeiXinAutoLoginRequest;
import com.aek56.microservice.auth.weixin.request.WeiXinBindingRequest;
import com.aek56.microservice.auth.weixin.request.WeiXinRepairMessageRequest;
import com.aek56.microservice.auth.weixin.request.WeiXinServiceMessageRequest;
import com.aek56.microservice.auth.weixin.response.JsSdkConfigResponse;
import com.aek56.microservice.auth.weixin.token.WeiXinAccessToken;
import com.aek56.microservice.auth.weixin.token.WeiXinJsCode2Session;
import com.aek56.microservice.auth.weixin.token.WeiXinOauth2Token;
import com.aek56.microservice.auth.weixin.userinfo.SNSUserInfo;
import com.github.pagehelper.StringUtil;
import com.google.gson.Gson;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;

/**
 * 接收微信验证消息
 *	
 * @author HongHui
 * @date   2017年11月29日
 */
@Api(value="WeiXinAuthController",description="微信操作",tags={"WeiXinAuthController-微信操作接口"})
@RestController
public class WeiXinAuthController extends BaseController{
	
	private static final Log logger = LogFactory.getLog(WeiXinAuthController.class);
	
	@Value("${jwt.header}")
	private String tokenHeader;
	@Value("${cookie.domain:aek.com}")
	private String cookieDomain;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private WeiXinService weiXinService;
	@Autowired
	private WxSysUserService wxSysUserService;
	@Autowired
	private SysUserService sysUserService;
	@Autowired
	private SystemService systemService;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	@Autowired
	private RedisRepository redisRepository;
	//微信公众号相关配置
	@Autowired
	private WeiXinConfig weiXinConfig;
	@Autowired
	private FileServerClientService fileServerClientService;
	
	/**
	 * 验证微信认证请求
	 */
	@ApiOperation(value = "验证微信认证请求", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = String.class)
	@RequestMapping(value="/weixin",method=RequestMethod.GET)
	@ResponseBody
	public String oauthWeiXinSignature(HttpServletRequest request,HttpServletResponse response){
		logger.debug("=================验证微信请求=================");
		String signature = request.getParameter("signature");
		String timestamp = request.getParameter("timestamp");
		String nonce = request.getParameter("nonce");
		String echostr = request.getParameter("echostr");
		logger.debug("#####微信加密签名：" + signature);
		logger.debug("#####时间戳：" + timestamp);
		logger.debug("#####随机数：" + nonce);
		logger.debug("#####随机字符串：" + echostr);
		//通过检验signature对请求进行校验，若校验成功则原样返回echostr，表示接入成功，否则接入失败
		if(WeiXinSignUtil.checkSignature(weiXinConfig.getToken(),signature, timestamp, nonce)){
			return echostr;
		}	
		return null;
	}
	
	/**
	 * 处理微信服务器发送过来的消息
	 */
	@ApiOperation(value = "处理微信服务器发送过来的消息", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = String.class)
	@RequestMapping(value="/weixin",method=RequestMethod.POST)
	@ResponseBody
	public String processWeiXinRequest(HttpServletRequest request,HttpServletResponse response) throws UnsupportedEncodingException{
		logger.debug("=================处理微信消息请求=================");
		//处理微信消息的接收、处理、响应
		//将请求、响应的编码均设为UTF-8，防止中文乱码
		request.setCharacterEncoding("UTF-8");
		response.setCharacterEncoding("UTF-8");
		// 调用核心业务类接收消息、处理消息
		String respXml = weiXinService.processWeiXinRequest(request);
		return respXml;
	}
	
	/**
	 * 获取最新微信access_token
	 */
	@ApiOperation(value = "获取最新微信access_token", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = String.class)
	@RequestMapping(value="/weixin/token",method=RequestMethod.GET)
	@ResponseBody
	public String getWeiXinAccessToken(){
		WeiXinAccessToken weiXinAccessToken = weiXinService.getWeiXinAccessToken(weiXinConfig.getAppId(),weiXinConfig.getAppSecret());
		if(null != weiXinAccessToken){
			return weiXinAccessToken.getAccessToken();
		}
		return null;
	}
	
	/**
	 * 授权后的回调请求处理
	 * @param request
	 * @param response
	 * @throws IOException 
	 * @throws ServletException 
	 */
	@RequestMapping(value="/weixin/callback",method=RequestMethod.GET)
	public void oauthCallBack(HttpServletRequest request, HttpServletResponse response){
		logger.info("============授权后的回调请求处理================");
		try{
			request.setCharacterEncoding("utf-8");
	        response.setCharacterEncoding("utf-8");
	        // 用户同意授权后，能获取到code
	        String code = request.getParameter("code");
	        String state = request.getParameter("state");
	        logger.info("code="+code);
	        logger.info("state="+state);
	        // 用户同意授权
	        if (!"authdeny".equals(code)) {
	        	logger.info("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	        	logger.info(weiXinConfig.toString());
	            // 获取网页授权access_token
	        	WeiXinOauth2Token weixinOauth2Token = WeiXinUtil.getOauth2AccessToken(weiXinConfig.getOauth2AccessTokenUrl(),weiXinConfig.getAppId(), weiXinConfig.getAppSecret(), code);
	            logger.info(weixinOauth2Token.toString());
	        	// 网页授权接口访问凭证
	            String accessToken = weixinOauth2Token.getAccessToken();
	            // 用户标识
	            String openId = weixinOauth2Token.getOpenId();
	            logger.info("openId="+openId);
	            // 获取用户信息
	            SNSUserInfo snsUserInfo = WeiXinUtil.getSNSUserInfo(weiXinConfig.getSnsUserInfoUrl(),accessToken, openId);
	            logger.info("用户信息="+snsUserInfo.toString());
	            //对openId加密处理
	            //openId = SecurityUtil.encryptDes(snsUserInfo.getOpenId());
	            openId = SecurityUtil.encryptBASE64(snsUserInfo.getOpenId().getBytes("UTF-8"));
	            String unionId = snsUserInfo.getUnionId();
	            System.out.println("微信callback用户信息="+snsUserInfo.toString());
	            System.out.println("openid="+openId);
	            System.out.println("unionId="+unionId);
	            //重定向至装备中心微信公众号登录页面，附带openId信息
            	response.sendRedirect(weiXinConfig.getBangdingLoginPageUrl()+"?openId="+openId);
	        }
	        logger.info("===================================================");
		} catch (Exception e){
			e.printStackTrace();
		}
	}
	
	/**
	 * 根据code获取微信用户openId
	 * @param code
	 * @return
	 */
	@ApiOperation(value = "根据code获取微信用户openId", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Result.class)
	@RequestMapping(value="/weixin/getOpenId",method=RequestMethod.GET)
	public Result<SNSUserInfo> getWeiXinUserOpenId(@RequestParam(required = true) String code){
		logger.info("==============根据code获取微信用户信息==============");
		logger.info("用户同意授权后获取code="+code);
		// 获取网页授权access_token
    	WeiXinOauth2Token weixinOauth2Token = WeiXinUtil.getOauth2AccessToken(weiXinConfig.getOauth2AccessTokenUrl(),weiXinConfig.getAppId(), weiXinConfig.getAppSecret(), code);
        // 网页授权接口访问凭证
        String accessToken = weixinOauth2Token.getAccessToken();
        // 用户标识
        String openId = weixinOauth2Token.getOpenId();
        // 获取用户信息
        SNSUserInfo snsUserInfo = WeiXinUtil.getSNSUserInfo(weiXinConfig.getSnsUserInfoUrl(),accessToken, openId);
		return response(snsUserInfo);
	}
	
	/**
	 * 系统用户与微信公众号用户绑定
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "系统用户与微信公众号用户绑定", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = Result.class)
	@PostMapping(value="/weixin/binding")
	public Result<Object> weiXinBinding(@RequestBody WeiXinBindingRequest request,HttpServletResponse response){
		try{
			String username = request.getUsername();
			String password = request.getPassword();
			String openId = request.getOpenId();
			String unionId = request.getUnionId();
			logger.info("username="+username);
			logger.info("password="+password);
			logger.info("openId="+openId);
			logger.info("unionId="+unionId);
			if (StringUtils.isBlank(username)){
				throw ExceptionFactory.create("B_001");
			} 
			SysUser user = systemService.getUserByLoginIdNoTenant(username);
			if (null == user) {
				throw ExceptionFactory.create("B_002");
			}
			if(StringUtils.isBlank(password)) {
				throw ExceptionFactory.create("B_003");
			}
			//密码校验
			if (!passwordEncoder.matches(password, user.getPassword())) {
				throw ExceptionFactory.create("B_004");
			}
			//账号停用
			if(!user.getEnable()){
				throw ExceptionFactory.create("B_005");
			}
			SysTenant sysTenant = systemService.getTenantInfo(user.getTenantId());
			//机构删除
			if(sysTenant.getDelFlag()){
				throw ExceptionFactory.create("B_006");
			}
			//账号待审核状态
			if(null != sysTenant && sysTenant.getAuditStatus() == 1){
				throw ExceptionFactory.create("B_007");
			}
			//账号审核未通过状态
			if(null != sysTenant && sysTenant.getAuditStatus() == 4){
				throw ExceptionFactory.create("B_008");
			}
			//机构被禁用
			if (!systemService.isTenantEnable(user.getTenantId())) {
				throw ExceptionFactory.create("B_009");
			}
			if(StringUtils.isBlank(openId)) {
				throw ExceptionFactory.create("B_010");
			}
			
			//解密
			openId = SecurityUtil.decryptDes(openId);
			if(wxSysUserService.exist(openId)){
				throw ExceptionFactory.create("B_011");
			}
			WxSysUser wxSysUser = wxSysUserService.getWxSysUser(user.getId());
			if(null != wxSysUser){
				throw ExceptionFactory.create("B_012");
			}
			logger.info("unionId="+unionId);
			//解密
			if(StringUtils.isNotBlank(unionId)&&!"null".equals(unionId)){
				unionId = SecurityUtil.decryptDes(unionId);
			}
			logger.info("=====================================");
			WxSysUser sysUser = new WxSysUser();
			sysUser.setOpenId(openId);
			sysUser.setUnionId(unionId);
			sysUser.setUserId(user.getId());
			sysUser.setPassword(SecurityUtil.encryptDes(password));
			logger.info("绑定用户信息="+sysUser.toString());
			wxSysUserService.saveWxSysUser(sysUser);
		}catch(Exception e){
			e.printStackTrace();
		}
		return response();
	}
	
	/**
	 * 判断系统用户与微信公众号用户是否绑定
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "判断系统用户与微信公众号用户是否绑定", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Boolean.class)
	@GetMapping(value="/weixin/isbinding")
	public Boolean isWeiXinBinding(@RequestParam(required = true) String openId){
		if(wxSysUserService.exist(openId)){
			return true;
		}
		return false;
	}
	
	/**
	 * 小程序判断token是否有效
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "判断token是否有效", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Boolean.class)
	@GetMapping(value="/weixin/validToken")
	public Boolean validWeiXinToken(@RequestParam(required = true) String token){
		System.out.println("==============");
		return jwtTokenUtil.validateToken(token);
	}
	
	/**
	 * 判断系统用户与微信公众号用户是否需要绑定提醒
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "判断系统用户与微信公众号用户是否需要绑定提醒", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Boolean.class)
	@GetMapping(value="/weixin/isNeedWeiXinBindingTips")
	public Result<Boolean> isNeedWeiXinBindingTips(@RequestParam(required = true) String openId,@RequestParam(required = true) Long userId){
		if(StringUtils.isNotBlank(openId)){
			//解密
			//openId = SecurityUtil.decryptDes(openId);
			openId = new String(SecurityUtil.decryptBASE64(openId),Charset.forName("UTF-8"));
		}
		WxSysUser wxSysUser = wxSysUserService.getWxSysUser(userId, openId);
		if(null != wxSysUser && !wxSysUser.getEnable()){
			return response(true);
		}
		return response(false);
	}
	
	/**
	 * 启用系统用户与微信公众号用户绑定关系
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "启用系统用户与微信公众号用户绑定关系", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Boolean.class)
	@GetMapping(value="/weixin/enableWeiXinBinding")
	public Result<Object> enableWeiXinBinding(@RequestParam(required = true) String openId,@RequestParam(required = true) Long userId){
		if(StringUtils.isNotBlank(openId)){
			//解密
			//openId = SecurityUtil.decryptDes(openId);
			openId = new String(SecurityUtil.decryptBASE64(openId),Charset.forName("UTF-8"));
		}
		WxSysUser wxSysUser = wxSysUserService.getWxSysUser(userId, openId);
		wxSysUser.setEnable(true);
		wxSysUserService.updateWxSysUser(wxSysUser);
		return response();
	}
	
	/**
	 * 停用系统用户与微信公众号用户绑定关系
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "停用系统用户与微信公众号用户绑定关系", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Boolean.class)
	@GetMapping(value="/weixin/disableWeiXinBinding")
	public Result<Object> disableWeiXinBinding(@RequestParam(required = true) String openId,@RequestParam(required = true) Long userId){
		if(StringUtils.isNotBlank(openId)){
			//解密
			//openId = SecurityUtil.decryptDes(openId);
			openId = new String(SecurityUtil.decryptBASE64(openId),Charset.forName("UTF-8"));
		}
		WxSysUser wxSysUser = wxSysUserService.getWxSysUser(userId, openId);
		wxSysUser.setEnable(false);
		wxSysUserService.updateWxSysUser(wxSysUser);
		return response();
	}
	
	/**
	 * 获取当前页面JsSdk配置信息
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "获取当前页面JsSdk配置信息", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Boolean.class)
	@GetMapping(value="/weixin/getJsSdkConfigInfo")
	public JsSdkConfigResponse getJsSdkConfigInfo(@RequestParam(required = true) String url){
		logger.info("当前页面URL="+url);
		//随机字符串
		String noncestr = WeiXinUtil.getRandomString(16);
		//当前时间戳
		String timestamp = String.valueOf(System.currentTimeMillis());
		//公众号appId
		String appId = weiXinConfig.getAppId();
		//accessToken
		WeiXinAccessToken wxAccessToken = weiXinService.getWxAccessToken();
		String content = "jsapi_ticket="+wxAccessToken.getJsApiTicket()+"&noncestr="+noncestr+"&timestamp="+timestamp+"&url="+url;
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-1");
			byte[] digest = messageDigest.digest(content.getBytes());
			String signature = WeiXinSignUtil.byteToStr(digest);
			return new JsSdkConfigResponse(appId,timestamp,noncestr,signature);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	@ApiOperation(value = "获取微信临时素材文件并上传", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = Boolean.class)
	@PostMapping(value="/weixin/uploadWeiXinImage")
	public Result<Object> uploadWeiXinImage(@RequestParam(required = true) String mediaId){
		logger.debug("==========获取微信临时素材文件并上传===========");
		WeiXinAccessToken wxAccessToken = weiXinService.getWxAccessToken();
		logger.debug("downloadWeiXinFileUrl="+weiXinConfig.getDownloadWeiXinFileUrl());
		logger.debug("accessToken="+wxAccessToken.getAccessToken());
		logger.debug("mediaId="+mediaId);
		MultipartFile file = WeiXinUtil.getFile(weiXinConfig.getDownloadWeiXinFileUrl(), wxAccessToken.getAccessToken(), mediaId);
		if(null != file){
			logger.debug("文件大小="+file.getSize());
			logger.info("文件名称="+file.getName());
			UploadInfo info = new UploadInfo();
			MultipartFile[] files = {file};
			info.setFiles(files);
			logger.debug(info.toString());
			Result<Object> result = fileServerClientService.zbzxUploadFile(file);
			if(null != result){
				logger.debug("上传文件返回结果="+result.toString());
			}
			logger.debug(null==result);
			logger.debug("========================================");
			return result;
		}
		throw new BusinessException("500","上传文件为空");
	}
	
	/**
	 * 绑定微信公众号的用户自动登录小程序
	 * @param request
	 * @param device
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "绑定微信公众号的用户自动登录小程序", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = Map.class)
	@PostMapping(value = "/weixin/autologin")
	public Map<String, Object> weiXinAutoLogin(@RequestBody WeiXinAutoLoginRequest request, Device device,
			HttpServletResponse response) {
		logger.debug(device);
		String deviceId = request.getDeviceId();
		Map<String, Object> map = new HashMap<String, Object>();
		if (deviceId == null || deviceId.length() < 10) {// 终端编号不能小于10
			map.put("code", 401);
			map.put("msg", "设备ID不能少于10位.");
			return map;
		}
		//微信用户授权后code
		String code = request.getCode();
		logger.info("微信用户同意授权后获取code="+code);
		
		if (StringUtils.isBlank(code)){
			map.put("code", 403);
			map.put("msg", "code不能为空");
			return map;
		} 
		
		WeiXinJsCode2Session weiXinJsCode2Session = WeiXinUtil.getJsCode2Session(weiXinConfig.getJsCode2SessionUrl(), weiXinConfig.getMiniAppId(), weiXinConfig.getMiniAppSecret(), code);
		if(null == weiXinJsCode2Session){
			map.put("code", 403);
			map.put("msg", "获取用户openid失败");
			return map;
		}
        // 用户标识
        String miniOpenId = weiXinJsCode2Session.getOpenId();
        // 用户唯一标识
        String unionId = weiXinJsCode2Session.getUnionid();
        System.out.println("小程序自动登录：mimiOpenId="+miniOpenId);
        System.out.println("小程序自动登录：unionId="+unionId);
        WxSysUser wxSysUser = wxSysUserService.getWxSysUserByUnionId(unionId);
        if(null == wxSysUser){
        	wxSysUser = wxSysUserService.getWxSysUserByMiniOpenId(miniOpenId);
        	if(null == wxSysUser){
        		map.put("code", "411");
				map.put("msg", "您未绑定的设备平台用户");
				return map;
        	}else{
        		if(StringUtil.isEmpty(wxSysUser.getUnionId())){
        			//更新
    				wxSysUser.setUnionId(unionId);
    				wxSysUserService.updateWxSysUser(wxSysUser);
        		}
        	}
        }else{
        	if(StringUtil.isEmpty(wxSysUser.getMiniOpenId())){
        		//更新
				wxSysUser.setMiniOpenId(miniOpenId);
				wxSysUserService.updateWxSysUser(wxSysUser);
        	}
        }
		
		SysUser user = systemService.getUserById(wxSysUser.getUserId());
		if (null == user) {
			map.put("code", "411");
			map.put("msg", "您绑定的用户不存在");
			return map;
		}
		if(!user.getEnable()){
			map.put("code", "411");
			map.put("msg", "您绑定的用户被禁用,请联系管理员");
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

		String key = deviceId + ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + user.getMobile();
		String authJson = redisRepository.get(key);
		if (StringUtils.isNotBlank(authJson)) {
			Gson gson = new Gson();
			TokenInfo tokenInfo = gson.fromJson(authJson, TokenInfo.class);
			map.put("code", 402);
			map.put("tokenKey", tokenHeader);
			map.put("token", tokenInfo.getToken());
			map.put("msg", "已登录.");
			
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			AuthUser userDetail = (AuthUser) authentication.getPrincipal();
			userDetail.setPassword(null);
			map.put("user_details", userDetail);
			
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
				.authenticate(new UsernamePasswordAuthenticationToken(user.getMobile(), SecurityUtil.decryptDes(wxSysUser.getPassword())));
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
		//返回当前用户信息
		tokenMap.put("user_details", userDetails);

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
	 * 发送微信维修消息
	 * @return
	 */
	@PostMapping(value = "/weixin/send/repair/message")
	@ApiOperation(value = "发送微信维修消息", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = Result.class)
	public Result<List<Map<String, Object>>> sendWeiXinRepairMessage(@RequestBody WeiXinRepairMessageRequest request){
		logger.debug("==============发送微信公众号维修消息==============");
		List<Map<String, Object>> responseMapList = new ArrayList<Map<String, Object>>();
		Map<String, Object> map = new HashMap<String, Object>();
		//获取机构下拥有接单、维修、验收权限用户集合
		List<SysUser> sysUsers = sysUserService.getWeiXinRepairMessageUsers(request.getTenantId(), request.getType());
		if(sysUsers.size() == 0){
			map.put("code", "401");
			map.put("msg", "该机构下没有拥有"+WeiXinConstants.WEIXIN_REPAIR_MESSAGE_TYPE_MAP.get(request.getType()) + "权限的用户");
			responseMapList.add(map);
			return response(responseMapList);
		}
		List<WxSysUser> wxSysUsers = new ArrayList<WxSysUser>();
		for (SysUser sysUser : sysUsers) {
			//用户被禁用或被删除时不能收到消息提醒
			if(sysUser.getEnable() && !sysUser.getDelFlag()){
				WxSysUser wxSysUser = wxSysUserService.getWxSysUser(sysUser.getId());
				if(null != wxSysUser){
					wxSysUsers.add(wxSysUser);
				}
			}
		}
		if(wxSysUsers.size() == 0){
			map.put("code", "401");
			map.put("msg", "该机构下拥有"+WeiXinConstants.WEIXIN_REPAIR_MESSAGE_TYPE_MAP.get(request.getType()) + "权限的用户未绑定微信公众号");
			responseMapList.add(map);
			return response(responseMapList);
		}
		
		//维修消息内容
		WeiXinRepairTemplate repairTemplate = new WeiXinRepairTemplate();
		String messageTypeName = WeiXinConstants.WEIXIN_REPAIR_MESSAGE_TYPE_MAP.get(request.getType());
        repairTemplate.setFirst("你有1个维修单需要"+messageTypeName+"，请及时处理");
        repairTemplate.setKeyword1(request.getApplyNo());
        repairTemplate.setKeyword2(request.getAssetsName());
        repairTemplate.setKeyword3(request.getAssetsNum());
        repairTemplate.setKeyword4(request.getAssetsDeptName());
        repairTemplate.setKeyword5(request.getReportRepairName());
        repairTemplate.setRemark("点击登录小程序可在消息中查看");
    	TreeMap<String, TreeMap<String, String>> messageBody = MapUtils.objectToTreeMap(repairTemplate);
    	
    	for (WxSysUser wxSysUser : wxSysUsers) {
    		String openId = wxSysUser.getOpenId();
			Long userId = wxSysUser.getUserId();
			logger.debug("消息接收者userId="+userId);
			logger.debug("消息接收者openId="+openId);
			//消息跳转小程序
	    	//Map<String,String> miniprogram = new HashMap<String,String>();
	        //miniprogram.put("appid",weiXinConfig.getMiniAppId());
	        //miniprogram.put("pagepath", weiXinConfig.getMiniRepairPagePath() + "?openId = " + openId +"&userId = " + userId);
			
			String redirectUrl = weiXinConfig.getOauth2AuthorizeUrl();
			redirectUrl = redirectUrl.replace("APPID", weiXinConfig.getAppId());
            redirectUrl = redirectUrl.replace("REDIRECT_URI", weiXinConfig.getWeixinCallBackUrl());
            redirectUrl = redirectUrl.replace("SCOPE", WeiXinScopeEnum.USERINFO.getScope());
            redirectUrl = redirectUrl.replace("STATE", "1");
            
	        TemplateMsgResult templateMsgResult = weiXinService.sendWeiXinMessage(openId, weiXinConfig.getRepairMessageTemplateId(), messageBody,null,redirectUrl);
	        Map<String,Object> responseMap = new HashMap<String,Object>();
	        responseMap.put("userId", String.valueOf(userId));
	        responseMap.put("openId", openId);
	        if(0 == templateMsgResult.getErrcode()){
	        	responseMap.put("code", "200");
	        	responseMap.put("msg", "消息发送成功");
			}else{
				responseMap.put("code", String.valueOf(templateMsgResult.getErrcode()));
				responseMap.put("msg", templateMsgResult.getErrmsg());
			}
	    	responseMapList.add(responseMap);
		}
    	return response(responseMapList);
	}
	
	/**
	 * 发送微信服务平台消息
	 * @return
	 */
	@PostMapping(value = "/weixin/send/service/message")
	@ApiOperation(value = "发送微信服务平台消息", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = Result.class)
	public Result<List<Map<String, Object>>> sendWeiXinServiceMessage(@RequestBody WeiXinServiceMessageRequest request){
		logger.debug("==============发送微信公众号服务平台消息==============");
		List<Map<String, Object>> responseMapList = new ArrayList<Map<String, Object>>();
		Map<String, Object> map = new HashMap<String, Object>();
		List<Long> tenantIds = request.getTenantIds();
		logger.debug("消息接收者机构ID集合 = " + tenantIds.toString());
		if(null == tenantIds || (null != tenantIds && tenantIds.size() == 0)){
			map.put("code", "401");
			map.put("msg", "机构ID集合不能为空");
			responseMapList.add(map);
			return response(responseMapList);
		}
		List<Long> hospitalTenantIds = new ArrayList<Long>();
		//只有医疗机构下用户才能能接收到消息
		for (Long tenantId : tenantIds) {
			SysTenant sysTenant = systemService.getTenantInfo(tenantId);
			if(null != sysTenant && TenantType.HOSPITAL.getNumber().equals(sysTenant.getTenantType())){
				hospitalTenantIds.add(tenantId);	
			}
		}
		if(hospitalTenantIds.size() == 0){
			map.put("code", "401");
			map.put("msg", "目标医疗机构ID集合为空");
			responseMapList.add(map);
			return response(responseMapList);
		}
		List<SysUser> sysUsers = systemService.getUserByTenantIds(hospitalTenantIds);
		//List<WxSysUser> toUsers = new ArrayList<WxSysUser>();
		Set<String> toOpenIds = new HashSet<String>();
		for (SysUser sysUser : sysUsers) {
			//用户被禁用或被删除时不能收到消息提醒
			if(sysUser.getEnable() && !sysUser.getDelFlag()){
				List<WxSysUser> wxSysUserList = wxSysUserService.getWxSysUserList(sysUser.getId());
				for (WxSysUser wxSysUser : wxSysUserList) {
					if(null != wxSysUser && wxSysUser.getEnable() && StringUtils.isNotBlank(wxSysUser.getOpenId())){
						toOpenIds.add(wxSysUser.getOpenId());
						//toUsers.add(wxSysUser);
					}
				}
			}
		}
		if(toOpenIds.size() == 0){
			map.put("code", "401");
			map.put("msg", "所选择的机构用户未绑定微信公众号");
			responseMapList.add(map);
			return response(responseMapList);
		}
		//服务平台消息内容
		WeiXinServiceTemplate weiXinServiceTemplate = new WeiXinServiceTemplate();
		String messageType = WeiXinConstants.WEIXIN_SERVICE_MESSAGE_TYPE_MAP.get(request.getType());
		weiXinServiceTemplate.setFirst("你有一条新的省装备管理中心消息，请及时查看");
		weiXinServiceTemplate.setKeyword1(messageType);
		weiXinServiceTemplate.setKeyword2(request.getPublishTime());
		weiXinServiceTemplate.setRemark("点击登录查看");
		TreeMap<String, TreeMap<String, String>> messageBody = MapUtils.objectToTreeMap(weiXinServiceTemplate);
		for (String openId : toOpenIds) {
			//String openId = wxSysUser.getOpenId();
			//Long userId = wxSysUser.getUserId();
			//logger.debug("消息接收者userId="+userId);
			logger.debug("消息接收者openId="+openId);
			//消息跳转小程序
	    	//Map<String,String> miniprogram = new HashMap<String,String>();
	        //miniprogram.put("appid", weiXinConfig.getMiniAppId());
	        //miniprogram.put("pagepath", weiXinConfig.getMiniServicePagePath() + "?openId = " + openId +"&userId = " + userId);
			
			String redirectUrl = weiXinConfig.getOauth2AuthorizeUrl();
			redirectUrl = redirectUrl.replace("APPID", weiXinConfig.getAppId());
            redirectUrl = redirectUrl.replace("REDIRECT_URI", weiXinConfig.getWeixinCallBackUrl());
            redirectUrl = redirectUrl.replace("SCOPE", WeiXinScopeEnum.USERINFO.getScope());
            redirectUrl = redirectUrl.replace("STATE", "1");
			
	        TemplateMsgResult templateMsgResult = weiXinService.sendWeiXinMessage(openId, weiXinConfig.getServiceMessageTemplateId(), messageBody, null,redirectUrl);
	        Map<String,Object> responseMap = new HashMap<String,Object>();
	        //responseMap.put("userId", String.valueOf(userId));
	        responseMap.put("openId", openId);
	        if(0 == templateMsgResult.getErrcode()){
	        	responseMap.put("code", "200");
	        	responseMap.put("msg", "消息发送成功");
			}else{
				responseMap.put("code", String.valueOf(templateMsgResult.getErrcode()));
				responseMap.put("msg", templateMsgResult.getErrmsg());
			}
	    	responseMapList.add(responseMap);
		}
		return response(responseMapList);
	}
	
	public static void main(String[] args) throws Exception {
		//String oauth2AccessTokenUrl = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=APPID&secret=SECRET&code=CODE&grant_type=authorization_code";
		//String appId = "wx6261aaf547d02565";
		//String appSecret = "62d37499b16edb2ec8bba2b300d63d5";
		//String code = "081FID8c2Wu2CP0ygK7c2M1K8c2FID8E";
		//WeiXinOauth2Token weixinOauth2Token = WeiXinUtil.getOauth2AccessToken(oauth2AccessTokenUrl,appId, appSecret, code);
		/*String openId = "o1BYH0uNTksQSvbPpkOIMHcI_sbI";
		openId = SecurityUtil.encryptBASE64(openId.getBytes("UTF-8"));
		//openId = SecurityUtil.encryptRSAPrivate(openId, "openId");
		System.out.println(openId);*/
		
		String openId = new String(SecurityUtil.decryptBASE64("2Pfcwu7M3vZ1mCfDsT7P4tnprT4byTFl3Pbgna=="),Charset.forName("UTF-8"));
		System.out.println(openId);
		
		/*Set<String> toOpenIds = new HashSet<String>();
		toOpenIds.add("o1BYH0uNTksQSvbPpkOIMHcI_sbI");
		toOpenIds.add("2");
		toOpenIds.add("3");
		toOpenIds.add("1");
		toOpenIds.add("o1BYH0uNTksQSvbPpkOIMHcI_sbI");
		for (String openId : toOpenIds) {
			System.out.println(openId);
		}*/
	}
}
