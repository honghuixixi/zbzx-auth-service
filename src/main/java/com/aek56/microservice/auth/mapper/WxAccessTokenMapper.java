package com.aek56.microservice.auth.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.aek56.microservice.auth.dao.CrudDao;
import com.aek56.microservice.auth.weixin.token.WeiXinAccessToken;

/**
 * 微信Token数据Mapper类
 *	
 * @author HongHui
 * @date   2017年12月1日
 */
@Mapper
public interface WxAccessTokenMapper extends CrudDao<WeiXinAccessToken> {

	/**
	 * 保存accessToken
	 * @param accessToken
	 */
	public void insertWxAccessToken(@Param("accessToken") WeiXinAccessToken accessToken);
	
	/**
	 * 获取最新accessToken
	 * @return
	 */
	public WeiXinAccessToken selectWxAccessToken();
	
}
