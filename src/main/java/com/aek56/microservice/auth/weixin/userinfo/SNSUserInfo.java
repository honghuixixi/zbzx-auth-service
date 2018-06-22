package com.aek56.microservice.auth.weixin.userinfo;

import java.util.List;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * 授权用户信息
 *	
 * @author HongHui
 * @date   2017年12月4日
 */
@ApiModel(value = "SNSUserInfo", description = "授权用户信息")
public class SNSUserInfo {

	// 用户标识
	@ApiModelProperty(value = "用户名openId")
    private String openId;
    // 用户昵称
	@ApiModelProperty(value = "用户昵称")
    private String nickname;
    // 性别（1是男性，2是女性，0是未知）
	@ApiModelProperty(value = " 性别（1是男性，2是女性，0是未知）")
    private int sex;
    // 国家
	@ApiModelProperty(value = "国家")
    private String country;
    // 省份
	@ApiModelProperty(value = "省份")
    private String province;
    // 城市
	@ApiModelProperty(value = "城市")
    private String city;
    // 用户头像链接
	@ApiModelProperty(value = "用户头像链接")
    private String headImgUrl;
    // 用户特权信息
	@ApiModelProperty(value = "用户特权信息")
    private List<String> privilegeList;
	//只有在用户将公众号绑定到微信开放平台帐号后，才会出现该字段
	@ApiModelProperty(value = "只有在用户将公众号绑定到微信开放平台帐号后，才会出现该字段")
	private String unionId;
    
	public String getOpenId() {
		return openId;
	}
	public void setOpenId(String openId) {
		this.openId = openId;
	}
	public String getNickname() {
		return nickname;
	}
	public void setNickname(String nickname) {
		this.nickname = nickname;
	}
	public int getSex() {
		return sex;
	}
	public void setSex(int sex) {
		this.sex = sex;
	}
	public String getCountry() {
		return country;
	}
	public void setCountry(String country) {
		this.country = country;
	}
	public String getProvince() {
		return province;
	}
	public void setProvince(String province) {
		this.province = province;
	}
	public String getCity() {
		return city;
	}
	public void setCity(String city) {
		this.city = city;
	}
	public String getHeadImgUrl() {
		return headImgUrl;
	}
	public void setHeadImgUrl(String headImgUrl) {
		this.headImgUrl = headImgUrl;
	}
	public List<String> getPrivilegeList() {
		return privilegeList;
	}
	public void setPrivilegeList(List<String> privilegeList) {
		this.privilegeList = privilegeList;
	}
	public String getUnionId() {
		return unionId;
	}
	public void setUnionId(String unionId) {
		this.unionId = unionId;
	}
	@Override
	public String toString() {
		return "SNSUserInfo [openId=" + openId + ", nickname=" + nickname + ", sex=" + sex + ", country=" + country
				+ ", province=" + province + ", city=" + city + ", headImgUrl=" + headImgUrl + ", privilegeList="
				+ privilegeList + ", unionId=" + unionId + "]";
	}
}
