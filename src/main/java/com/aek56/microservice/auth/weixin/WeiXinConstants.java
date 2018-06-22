package com.aek56.microservice.auth.weixin;

import java.util.HashMap;
import java.util.Map;

/**
 * 微信相关常量配置
 *	
 * @author HongHui
 * @date   2017年11月29日
 */
public class WeiXinConstants {
	
	/**
	 * 微信公众号APPID
	 *//*
    public static String APPID = "wx19d952d6186a9a82";
    
    *//**
     * 微信公众号APPID
     *//*
    public static String APPSECRET = "2200f2f58105600edfb0d3d0d9b111f3";
    
    *//**
     * 获取ACCESS_TOKEN接口
     *//*
    public static String GET_ACCESSTOKEN_URL = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=APPSECRET";
    
    *//**
     * 菜单创建(POST)
     *//*
    public static String POST_MENU_CREATE_URL = "https://api.weixin.qq.com/cgi-bin/menu/create?access_token=ACCESS_TOKEN";
    
    *//**
     * 获取微信用户信息(GET)
     *//*
    public static String GET_USER_INFO_URL = "https://api.weixin.qq.com/cgi-bin/user/info?access_token=ACCESS_TOKEN&openid=OPENID";
    
    *//**
     * 获取网页授权凭证(GET)
     *//*
    public static String GET_OAUTH2_ACCESSTOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=APPID&secret=SECRET&code=CODE&grant_type=authorization_code";
    
    *//**
     * 发送模板消息(POST)
     *//*
    public static String POST_SEND_TEMPLATE_MSG_URL = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=ACCESS_TOKEN";
    
    *//**
     * 请求网页授权页面
     *//*
    public static String GET_OAUTH2_AUTHORIZE_URL = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=APPID&redirect_uri=REDIRECT_URI&response_type=code&scope=SCOPE&state=STATE";
    
    *//**
     * ACCESS_TOKEN有效时间(单位：ms)
     *//*
    public static int EFFECTIVE_TIME = 700000;

	*//**
	 * 微信接入Token,用于验证微信接入
	 *//*
	public static String TOKEN = "aek56.cc";
	
	*//**
	 * 微信小程序APPID
	 *//*
	public static String WEIXIN_MINI_APPID = "wxee5957e2cc752628";
	
	*//**
	 * 点击微信维修消息，跳转页面地址
	 *//*
	public static String WEIXIN_MINI_REPAIR_PAGE_PATH = "pages/workplat/workplat"; 
	
	*//**
	 * 微信维修消息模板ID
	 *//*
	public static String WEIXIN_MINI_REPAIR_MESSAGE_TEMPLATE_ID = "QljNIv-OyzZpcN8TONYTCF_oYuyFUK5x041NXm2AdhY";
	
	*//**
	 * 点击微信服务平台消息，跳转页面地址
	 *//*
	public static String WEIXIN_MINI_SERVICE_PAGE_PATH = "pages/workplat/workplat"; 
	
	*//**
	 * 微信服务平台消息模板ID
	 *//*
	public static String WEIXIN_MINI_SERVICE_MESSAGE_TEMPLATE_ID = "f7frkYjSmM3vGLtc-cVPhnb46RwBZST9wgGeLezdesI";*/
	
	//微信维修消息类型
	public final static Map<Integer, String> WEIXIN_REPAIR_MESSAGE_TYPE_MAP = new HashMap<Integer, String>();
	static {
		//类型：1=接单、2=维修、3=验收
		WEIXIN_REPAIR_MESSAGE_TYPE_MAP.put(1, "接单");
		WEIXIN_REPAIR_MESSAGE_TYPE_MAP.put(2, "维修");
		WEIXIN_REPAIR_MESSAGE_TYPE_MAP.put(3, "验收");
	}
	
	//服务平台消息类型
	public final static Map<Integer, String> WEIXIN_SERVICE_MESSAGE_TYPE_MAP = new HashMap<Integer, String>();
	static {
		//类型：0=通知、1=消息、2=文章
		WEIXIN_SERVICE_MESSAGE_TYPE_MAP.put(0, "通知");
		WEIXIN_SERVICE_MESSAGE_TYPE_MAP.put(1, "消息");
		WEIXIN_SERVICE_MESSAGE_TYPE_MAP.put(2, "资料");
	}
}
