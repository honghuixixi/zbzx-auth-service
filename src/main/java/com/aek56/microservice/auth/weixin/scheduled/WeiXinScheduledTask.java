package com.aek56.microservice.auth.weixin.scheduled;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.aek56.microservice.auth.weixin.WeiXinService;
import com.aek56.microservice.auth.weixin.config.WeiXinConfig;
import com.aek56.microservice.auth.weixin.token.WeiXinAccessToken;

/**
 * 微信获取接入Token定时任务类
 * 
 * @author HongHui
 * @date 2017年12月1日
 */
@Component
public class WeiXinScheduledTask {

	private static final Log logger = LogFactory.getLog(WeiXinScheduledTask.class);

	@Autowired
	private WeiXinService weiXinService;
	//微信公众号相关配置
	@Autowired
	private WeiXinConfig weiXinConfig;

	/**
	 * 每隔1小时执行一次获取accessToken
	 */
	@Scheduled(cron = "0 0 0/1 * * ?")
	public void getWeiXinAccessTokenTask() {
		logger.info("===================获取微信接入AccessToken并保存===============");
		WeiXinAccessToken accessToken = weiXinService.getRemoteWeiXinAccessToken(weiXinConfig.getAppId(), weiXinConfig.getAppSecret());
		logger.info("===================AccessToken="+accessToken.toString());
		weiXinService.saveAccessToken(accessToken);
	}

}
