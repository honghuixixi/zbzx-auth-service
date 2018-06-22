package com.aek56.microservice.auth.weixin.menu;

import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.aek56.microservice.auth.weixin.WeiXinConstants;
import com.aek56.microservice.auth.weixin.WeiXinUtil;
import com.aek56.microservice.auth.weixin.enums.WeiXinScopeEnum;
import com.aek56.microservice.auth.weixin.token.Token;
import com.aek56.microservice.auth.weixin.token.WeiXinAccessToken;
import com.google.gson.Gson;

/**
 * 菜单管理类
 *	
 * @author HongHui
 * @date   2017年12月4日
 */
public class MenuManager {

	private static final Log logger = LogFactory.getLog(MenuManager.class);
	
    /**
	 * 微信公众号APPID
	 */
    //public static String APPID = "wx19d952d6186a9a82";
    
    /**
	 * 装备中心微信公众号APPID
	 */
    public static String APPID="wx6261aaf547d02565";
    
	/**
	 * 正式微信公众号APPID
	 */
    //public static String APPID = "wx2109bf24cfd01eb0";
    
    /**
     * 微信公众号APPSECRET
     */
    //public static String APPSECRET = "2200f2f58105600edfb0d3d0d9b111f3";
    
    /**
     * 装备中心微信公众号APPSECRET
     */
    public static String APPSECRET = "a1f493c4ff59d62c62579d542b21906a";
    
    /**
     * 正式微信公众号APPSECRET
     */
    //public static String APPSECRET = "9f74f8d6529f90b367b385a81d4a5efa";
    
	/**
	 * 微信小程序APPID
	 */
	//public static String WEIXIN_MINI_APPID = "wxee5957e2cc752628";
	
	/**
	 * 线上微信小程序APPID
	 */
	public static String WEIXIN_MINI_APPID = "wxbadbf2216ad2568b";
    
    /**
     * 请求网页授权页面
     */
    public static String GET_OAUTH2_AUTHORIZE_URL = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=APPID&redirect_uri=REDIRECT_URI&response_type=code&scope=SCOPE&state=STATE";
	
    /**
     * 获取ACCESS_TOKEN接口
     */
    public static String GET_ACCESSTOKEN_URL = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=APPSECRET";
    
    /**
     * 菜单创建(POST)
     */
    public static String POST_MENU_CREATE_URL = "https://api.weixin.qq.com/cgi-bin/menu/create?access_token=ACCESS_TOKEN";
    
	public static void main(String[] args) {
		// 调用接口获取access_token
		/*String requestUrl = GET_ACCESSTOKEN_URL.replace("APPID" , APPID).replace("APPSECRET" , APPSECRET);
        String accessTokenJson = WeiXinUtil.httpsRequest(requestUrl , "GET" , null);
        if(StringUtils.isNotBlank(accessTokenJson)){
        	Token token = new Gson().fromJson(accessTokenJson, Token.class);
        	String accessToken = token.getAccess_token();
        	// 调用接口创建菜单
            int result = WeiXinUtil.createMenu(POST_MENU_CREATE_URL,getMenu(), accessToken);
            // 判断菜单创建结果
            if (0 == result)
            	logger.info("菜单创建成功！");
            else
            	logger.info("菜单创建失败，错误码：" + result);
        }*/
        
        String accessToken = "7_gtiGeINdJoLuEz_ViPrGZciB6Zyqt-TgNykdy4kCRrFBrQ3ZUevY8-OzqhPRqZLZcAFqCLPJPLC0VzGxwBvOZyzTwqC-XEpEBfoGRCTaHy-p1U9yUbsJh8qe9yVDBz6mWfQrDg3pUgv1fcNPCYLfADAWSF";
    	// 调用接口创建菜单
        int result = WeiXinUtil.createMenu(POST_MENU_CREATE_URL,getMenu(), accessToken);
        // 判断菜单创建结果
        if (0 == result)
        	logger.info("菜单创建成功！");
        else
        	logger.info("菜单创建失败，错误码：" + result);
	}
	
	/**
     * 组装菜单数据
     * 
     * @return
     */
    private static Menu getMenu() {
        /*CommonButton btn11 = new CommonButton();
        btn11.setName("天气预报");
        btn11.setType("view");
        btn11.setKey("11");
        String requestUrl = WeiXinConstants.GET_OAUTH2_AUTHORIZE_URL;
        requestUrl = requestUrl.replace("APPID", WeiXinConstants.APPID);
        requestUrl = requestUrl.replace("REDIRECT_URI", "https://ebey.aek56.com/#/access/login");
        requestUrl = requestUrl.replace("SCOPE", WeiXinScopeEnum.USERINFO.getScope());
        requestUrl = requestUrl.replace("STATE", "1");
        btn11.setUrl(requestUrl);

        CommonButton btn12 = new CommonButton();
        btn12.setName("公交查询");
        btn12.setType("click");
        btn12.setKey("12");

        CommonButton btn13 = new CommonButton();
        btn13.setName("周边搜索");
        btn13.setType("click");
        btn13.setKey("13");

        CommonButton btn14 = new CommonButton();
        btn14.setName("历史上的今天");
        btn14.setType("click");
        btn14.setKey("14");

        CommonButton btn21 = new CommonButton();
        btn21.setName("歌曲点播");
        btn21.setType("click");
        btn21.setKey("21");

        CommonButton btn22 = new CommonButton();
        btn22.setName("经典游戏");
        btn22.setType("click");
        btn22.setKey("22");

        CommonButton btn23 = new CommonButton();
        btn23.setName("美女电台");
        btn23.setType("click");
        btn23.setKey("23");

        CommonButton btn24 = new CommonButton();
        btn24.setName("人脸识别");
        btn24.setType("click");
        btn24.setKey("24");

        CommonButton btn25 = new CommonButton();
        btn25.setName("聊天唠嗑");
        btn25.setType("click");
        btn25.setKey("25");

        CommonButton btn31 = new CommonButton();
        btn31.setName("Q友圈");
        btn31.setType("click");
        btn31.setKey("31");

        CommonButton btn32 = new CommonButton();
        btn32.setName("电影排行榜");
        btn32.setType("click");
        btn32.setKey("32");

        CommonButton btn33 = new CommonButton();
        btn33.setName("幽默笑话");
        btn33.setType("click");
        btn33.setKey("33");

        
        *//**
         * 微信：  mainBtn1,mainBtn2,mainBtn3底部的三个一级菜单。
         *//*
        
        ComplexButton mainBtn1 = new ComplexButton();
        mainBtn1.setName("生活助手");
        //一级下有4个子菜单
        mainBtn1.setSub_button(new CommonButton[] { btn11, btn12, btn13, btn14 });

        
        ComplexButton mainBtn2 = new ComplexButton();
        mainBtn2.setName("休闲驿站");
        mainBtn2.setSub_button(new CommonButton[] { btn21, btn22, btn23, btn24, btn25 });

        
        ComplexButton mainBtn3 = new ComplexButton();
        mainBtn3.setName("更多体验");
        mainBtn3.setSub_button(new CommonButton[] { btn31, btn32, btn33 });*/
    	
    	
    	/**
         * 封装整个菜单
         */
        /*Menu menu = new Menu();
        menu.setButton(new Button[] { mainBtn1, mainBtn2, mainBtn3 });*/

    	/*CommonButton btn11 = new CommonButton();
        btn11.setName("账号绑定");
        btn11.setType("view");
        btn11.setKey("11");
        String requestUrl1 = GET_OAUTH2_AUTHORIZE_URL;
        requestUrl1 = requestUrl1.replace("APPID", APPID);
        requestUrl1 = requestUrl1.replace("REDIRECT_URI", "https://ebey.aek56.com/api/oauth/weixin/callback");
        requestUrl1 = requestUrl1.replace("SCOPE", WeiXinScopeEnum.USERINFO.getScope());
        requestUrl1 = requestUrl1.replace("STATE", "1");
        btn11.setUrl(requestUrl1);
        
        MiniButton btn12 = new MiniButton();
        btn12.setName("登录小程序");
        btn12.setType("miniprogram");
        //btn12.setType("view");
        btn12.setKey("22");
        btn12.setUrl("https://ebey.aek56.com");
        btn12.setAppid(WEIXIN_MINI_APPID);
        btn12.setPagepath("pages/workplat/workplat");*/
    	
    	CommonButton btn11 = new CommonButton();
        btn11.setName("登录");
        btn11.setType("view");
        btn11.setKey("11");
        String requestUrl1 = GET_OAUTH2_AUTHORIZE_URL;
        requestUrl1 = requestUrl1.replace("APPID", APPID);
        requestUrl1 = requestUrl1.replace("REDIRECT_URI", "https://ebey.aek56.com/api/zbzx/oauth/weixin/callback");
        requestUrl1 = requestUrl1.replace("SCOPE", WeiXinScopeEnum.USERINFO.getScope());
        requestUrl1 = requestUrl1.replace("STATE", "1");
        btn11.setUrl(requestUrl1);
        
        Menu menu = new Menu();
        menu.setButton(new Button[] { btn11});
        
        return menu;
    }
}
