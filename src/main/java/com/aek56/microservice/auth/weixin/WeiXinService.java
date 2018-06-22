package com.aek56.microservice.auth.weixin;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.aek56.microservice.auth.entity.WxSysUser;
import com.aek56.microservice.auth.mapper.WxAccessTokenMapper;
import com.aek56.microservice.auth.mapper.WxSysUserMapper;
import com.aek56.microservice.auth.weixin.config.WeiXinConfig;
import com.aek56.microservice.auth.weixin.enums.WeiXinScopeEnum;
import com.aek56.microservice.auth.weixin.message.response.TextMessage;
import com.aek56.microservice.auth.weixin.message.template.TemplateMsgResult;
import com.aek56.microservice.auth.weixin.message.template.WeiXinTemplateMsg;
import com.aek56.microservice.auth.weixin.token.Token;
import com.aek56.microservice.auth.weixin.token.WeiXinAccessToken;
import com.alibaba.fastjson.JSON;
import com.google.gson.Gson;

/**
 *  处理微信消息业务类
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
@Service
@Transactional
public class WeiXinService {
	
	private static final Log logger = LogFactory.getLog(WeiXinService.class);
	
	@Autowired
	private WxAccessTokenMapper wxAccessTokenMapper;
	//微信公众号相关配置
	@Autowired
	private WeiXinConfig weiXinConfig;
	@Autowired
	private WxSysUserMapper wxSysUserMapper;
	
	
	
	/**
	 * 保存微信接入Token保存至数据库
	 * @param accessToken
	 */
	public void saveAccessToken(WeiXinAccessToken accessToken){
		wxAccessTokenMapper.insertWxAccessToken(accessToken);
	}
	
	/**
	 * 获取最新微信接入Token
	 * @return
	 */
	public WeiXinAccessToken getWxAccessToken(){
		return wxAccessTokenMapper.selectWxAccessToken();
	}
	
	/**
	 * 获取微信接入Token
	 * @param appId
	 * @param appSecret
	 * @return
	 */
	public WeiXinAccessToken getWeiXinAccessToken(String appId,String appSecret){
		WeiXinAccessToken accessToken = new WeiXinAccessToken();
		Token token = getAccessToken(appId, appSecret);
		if(null != token){
			accessToken.setAccessToken(token.getAccess_token());
			accessToken.setExpiresIn(token.getExpires_in());
			accessToken.setCreateTime(new Date());
			return accessToken;
		}
        return null;
	}
	
	/**
	 * 获取微信服务器最新接入Token
	 * @param appId
	 * @param appSecret
	 * @return
	 */
	public WeiXinAccessToken getRemoteWeiXinAccessToken(String appId,String appSecret){
		String requestUrl = weiXinConfig.getAccessTokenUrl().replace("APPID" , appId).replace("APPSECRET" , appSecret);
        String accessTokenJson = WeiXinUtil.httpsRequest(requestUrl , "GET" , null);
        if(StringUtils.isNotBlank(accessTokenJson)){
        	Token token = new Gson().fromJson(accessTokenJson, Token.class);
        	WeiXinAccessToken weiXinAccessToken =  new WeiXinAccessToken();
        	weiXinAccessToken.setAccessToken(token.getAccess_token());
        	weiXinAccessToken.setExpiresIn(token.getExpires_in());
        	weiXinAccessToken.setCreateTime(new Date());
        	String ticket = WeiXinUtil.getJsApiTicket(weiXinConfig.getJsApiGetTicketUrl(), token.getAccess_token());
        	weiXinAccessToken.setJsApiTicket(ticket);
            return weiXinAccessToken;
        }
        return null;
	}
	
	/**
	 * 获取微信接入Token
	 * @param appId
	 * @param appSecret
	 * @return
	 */
	private Token getAccessToken(String appId,String appSecret){
		//获取数据库缓存最新access_token
		WeiXinAccessToken accessToken =  getWxAccessToken();
		if(null != accessToken){
			Date createTime = accessToken.getCreateTime();
			// 在某一个时间点上加两小时的写法  
			 Calendar calendar = Calendar.getInstance();  
			// 此处setTime为Date类型  
			calendar.setTime(createTime);  
			// 加上两小时  
			calendar.add(Calendar.HOUR, Integer.parseInt((accessToken.getExpiresIn()/60/60)+""));
			Date now = new Date();
			// 当前时间大于获取token时间并且小于token有效截止时间，直接返回
			if(now.getTime() < calendar.getTimeInMillis() && now.getTime() > createTime.getTime()){
				Token token = new Token();
				token.setAccess_token(accessToken.getAccessToken());
				token.setExpires_in(accessToken.getExpiresIn());
				return token;
			}
		}
		//数据库中无缓存access_token或者已失效，则再次获取最新access_token
		WeiXinAccessToken weiXinAccessToken = getRemoteWeiXinAccessToken(appId, appSecret);
		if(null != weiXinAccessToken){
			wxAccessTokenMapper.insertWxAccessToken(weiXinAccessToken);
			Token token = new Token();
			token.setAccess_token(weiXinAccessToken.getAccessToken());
			token.setExpires_in(weiXinAccessToken.getExpiresIn());
			return token;
		}
        return null;
	}
	
	/**
	 * 发送微信公众号推送消息
	 * @param openId
	 * @param msgTemplateId
	 * @param params
	 * @param miniprogram
	 * @return
	 */
	public TemplateMsgResult sendWeiXinMessage(String openId,String msgTemplateId,TreeMap<String, TreeMap<String, String>> params,Map<String,String> miniprogram,String url){
        WeiXinTemplateMsg wechatTemplateMsg = new WeiXinTemplateMsg();  
        wechatTemplateMsg.setTemplate_id(msgTemplateId);    
        wechatTemplateMsg.setTouser(openId);   
        wechatTemplateMsg.setData(params);  
        wechatTemplateMsg.setUrl(url);
        wechatTemplateMsg.setMiniprogram(miniprogram);
		Token token = getAccessToken(weiXinConfig.getAppId(),weiXinConfig.getAppSecret());
		TemplateMsgResult templateMsgResult = WeiXinUtil.sendWeiXinTemplateMsg(weiXinConfig.getSendTemplateMsgUrl(),token.getAccess_token(),JSON.toJSONString(wechatTemplateMsg));
		return templateMsgResult;
	}
	
	/**
	 * 处理微信服务器发来的请求
	 * @param request
	 * @return
	 */
	public String processWeiXinRequest(HttpServletRequest request){
		String respXml = null;
		String respContent = null;
        try {
            // 调用parseXml方法解析请求消息
            Map<String, String> requestMap = WeiXinMessageUtil.parseWeiXinXml(request);
            // 发送方帐号
            String fromUserName = requestMap.get("FromUserName");
            // 开发者微信号
            String toUserName = requestMap.get("ToUserName");
            // 消息类型
            String msgType = requestMap.get("MsgType");
            
            logger.info("发送方账号FromUserName = " + fromUserName);
            logger.info("开发者微信号toUserName = " + toUserName);
            logger.info("消息类型msgType = " + msgType);
            
            // 回复文本消息
            TextMessage textMessage = new TextMessage();
            textMessage.setToUserName(fromUserName);
            textMessage.setFromUserName(toUserName);
            textMessage.setCreateTime(new Date().getTime());
            textMessage.setMsgType(WeiXinMessageUtil.RESP_MESSAGE_TYPE_TEXT);

            // 文本消息
            if (msgType.equals(WeiXinMessageUtil.REQ_MESSAGE_TYPE_TEXT)) {
                //respContent = "您发送的是文本消息！";
            	logger.info("您发送的是文本消息！");
            }
            // 图片消息
            else if (msgType.equals(WeiXinMessageUtil.REQ_MESSAGE_TYPE_IMAGE)) {
                //respContent = "您发送的是图片消息！";
            	logger.info("您发送的是图片消息！");
            }
            // 语音消息
            else if (msgType.equals(WeiXinMessageUtil.REQ_MESSAGE_TYPE_VOICE)) {
                //respContent = "您发送的是语音消息！";
            	logger.info("您发送的是语音消息！");
            }
            // 视频消息
            else if (msgType.equals(WeiXinMessageUtil.REQ_MESSAGE_TYPE_VIDEO)) {
                //respContent = "您发送的是视频消息！";
            	logger.info("您发送的是视频消息！");
            }
            // 视频消息
            else if (msgType.equals(WeiXinMessageUtil.REQ_MESSAGE_TYPE_SHORTVIDEO)) {
                //respContent = "您发送的是小视频消息！";
            	logger.info("您发送的是小视频消息！");
            }
            // 地理位置消息
            else if (msgType.equals(WeiXinMessageUtil.REQ_MESSAGE_TYPE_LOCATION)) {
                //respContent = "您发送的是地理位置消息！";
            	logger.info("您发送的是地理位置消息！");
            }
            // 链接消息
            else if (msgType.equals(WeiXinMessageUtil.REQ_MESSAGE_TYPE_LINK)) {
                //respContent = "您发送的是链接消息！";
            	logger.info("您发送的是链接消息！");
            }
            // 事件推送
            else if (msgType.equals(WeiXinMessageUtil.REQ_MESSAGE_TYPE_EVENT)) {
                // 事件类型
                String eventType = requestMap.get("Event");
                // 关注
                if (eventType.equals(WeiXinMessageUtil.EVENT_TYPE_SUBSCRIBE)) {
                	StringBuilder resp = new StringBuilder();
                	resp.append("欢迎关注浙江省医学装备管理中心工作平台\n");
                	resp.append("官网：http://www.zjyxzb.org.cn/f\n");
                	resp.append("问题咨询：zjyxzb@126.com\n");
                	resp.append("\n");
                	String requestUrl1 = weiXinConfig.getOauth2AuthorizeUrl();
                    requestUrl1 = requestUrl1.replace("APPID", weiXinConfig.getAppId());
                    requestUrl1 = requestUrl1.replace("REDIRECT_URI", weiXinConfig.getWeixinCallBackUrl());
                    requestUrl1 = requestUrl1.replace("SCOPE", WeiXinScopeEnum.USERINFO.getScope());
                    requestUrl1 = requestUrl1.replace("STATE", "1");
                    resp.append("<a href='"+requestUrl1+"'>点击登录平台账号</a>");
                	logger.info("关注欢迎信息=" + resp.toString());
                    respContent = resp.toString();
                }
                // 取消关注
                else if (eventType.equals(WeiXinMessageUtil.EVENT_TYPE_UNSUBSCRIBE)) {
                    // TODO 取消订阅后用户不会再收到公众账号发送的消息，因此不需要回复
                	//respContent = "为什么取消关注呢！";
                	logger.info("取消关注公众号");
                	//取消关注公众号时清除微信用户与平台用户绑定关系
                	List<WxSysUser> wxSysUserList = wxSysUserMapper.selectWxSysUserByOpenIdList(fromUserName);
                	logger.info("微信号："+fromUserName+"绑定的平台状态如下：");
                	for (WxSysUser wxSysUser : wxSysUserList) {
                		logger.info(wxSysUser.toString());
                		wxSysUserMapper.deleteById(wxSysUser.getId());
					}
                }
                // 扫描带参数二维码
                else if (eventType.equals(WeiXinMessageUtil.EVENT_TYPE_SCAN)) {
                    // TODO 处理扫描带参数二维码事件
                	logger.info("处理扫描带参数二维码事件");
                }
                // 上报地理位置
                else if (eventType.equals(WeiXinMessageUtil.EVENT_TYPE_LOCATION)) {
                    // TODO 处理上报地理位置事件
                	logger.info("处理上报地理位置事件");
                }
                // 自定义菜单
                else if (eventType.equals(WeiXinMessageUtil.EVENT_TYPE_CLICK)) {
                    // TODO 处理菜单点击事件
                	logger.info("处理菜单点击事件");
                }
            }
            if(StringUtils.isNotBlank(respContent)){
            	// 设置文本消息的内容
                textMessage.setContent(respContent);
                // 将文本消息对象转换成xml
                respXml = WeiXinMessageUtil.messageToXml(textMessage);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
		return respXml;
	}
	
	
	
}
