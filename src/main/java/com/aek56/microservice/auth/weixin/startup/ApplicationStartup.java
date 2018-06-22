package com.aek56.microservice.auth.weixin.startup;

import javax.servlet.ServletContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.ServletContextAware;

import com.aek56.microservice.auth.weixin.WeiXinService;
import com.aek56.microservice.auth.weixin.config.WeiXinConfig;
import com.aek56.microservice.auth.weixin.token.WeiXinAccessToken;

/**
 * 容器重启时，需将
 *	
 * @author HongHui
 * @date   2017年12月1日
 */
@Component
public class ApplicationStartup implements InitializingBean,ServletContextAware {

	private static final Logger logger = LoggerFactory.getLogger(ApplicationStartup.class);

	@Autowired
	private WeiXinService weiXinService;
	//微信公众号相关配置
	@Autowired
	private WeiXinConfig weiXinConfig;
	
	@Override
	public void setServletContext(ServletContext servletContext) {
		logger.info("===================应用启动时获取微信接入AccessToken并保存===============");
		WeiXinAccessToken accessToken = weiXinService.getRemoteWeiXinAccessToken(weiXinConfig.getAppId(), weiXinConfig.getAppSecret());
		logger.info("===================AccessToken="+accessToken.toString());
		weiXinService.saveAccessToken(accessToken);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
	}
}
