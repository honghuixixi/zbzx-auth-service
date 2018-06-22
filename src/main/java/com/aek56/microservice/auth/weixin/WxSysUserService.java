package com.aek56.microservice.auth.weixin;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.aek56.microservice.auth.entity.WxSysUser;
import com.aek56.microservice.auth.mapper.WxSysUserMapper;

/**
 *  微信用户绑定服务
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
@Service
@Transactional
public class WxSysUserService {
	
	@Autowired
	private WxSysUserMapper wxSysUserMapper;
	
	/**
	 * 保存微信用户绑定关系保存至数据库
	 * @param wxSysUser
	 */
	public void saveWxSysUser(WxSysUser wxSysUser){
		wxSysUserMapper.insertWxSysUser(wxSysUser);
	}
	
	/**
	 * 更新微信用户绑定关系保存至数据库
	 * @param wxSysUser
	 */
	public void updateWxSysUser(WxSysUser wxSysUser){
		wxSysUserMapper.updateWxSysUser(wxSysUser);
	}
	
	/**
	 * 判断openid是否已经绑定用户
	 * @return
	 */
	public boolean exist(String openId){
		int count = wxSysUserMapper.countWxSysUser(openId);
		return count > 0 ? true : false;
	}
	
	/**
	 * 查询OpenId绑定的用户
	 * @param openId
	 * @return
	 */
	public WxSysUser getWxSysUser(String openId){
		return wxSysUserMapper.selectWxSysUserByOpenId(openId);
	}
	
	/**
	 * 查询UnionId绑定的用户
	 * @param unionId
	 * @return
	 */
	public WxSysUser getWxSysUserByUnionId(String unionId){
		return wxSysUserMapper.selectWxSysUserByUnionId(unionId);
	}
	
	/**
	 * 查询mini_open_id绑定的用户
	 * @param miniOpenId
	 * @return
	 */
	public WxSysUser getWxSysUserByMiniOpenId(String miniOpenId){
		return wxSysUserMapper.selectWxSysUserByMiniOpenId(miniOpenId);
	}
	
	/**
	 * 查询userId绑定的微信用户
	 * @param openId
	 * @return
	 */
	public WxSysUser getWxSysUser(Long userId){
		return wxSysUserMapper.selectWxSysUserByUserId(userId);
	}
	
	/**
	 * 查询userId,openId绑定的微信用户
	 * @param openId
	 * @param userId
	 * @return
	 */
	public WxSysUser getWxSysUser(Long userId,String openId){
		return wxSysUserMapper.selectWxSysUserByUserIdOpenId(userId,openId);
	}
	
	/**
	 * 查询userId绑定的微信用户
	 * @param openId
	 * @return
	 */
	public List<WxSysUser> getWxSysUserList(Long userId){
		return wxSysUserMapper.selectWxSysUserByUserIdList(userId);
	}
}
