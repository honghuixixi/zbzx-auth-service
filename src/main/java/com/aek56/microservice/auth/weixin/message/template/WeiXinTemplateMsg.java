package com.aek56.microservice.auth.weixin.message.template;

import java.util.Map;
import java.util.TreeMap;

/**
 * 微信模板消息
 *	
 * @author HongHui
 * @date   2017年12月4日
 */
public class WeiXinTemplateMsg {

	// 接收者OPENID
	private String touser;
	// 消息模板ID
	private String template_id;
	// 模板跳转链接
	private String url;
	//跳小程序需要的数据
	private Map<String,String> miniprogram;
	//data数据 
	private TreeMap<String, TreeMap<String, String>> data;
	
	public String getTouser() {
		return touser;
	}
	public void setTouser(String touser) {
		this.touser = touser;
	}
	public String getTemplate_id() {
		return template_id;
	}
	public void setTemplate_id(String template_id) {
		this.template_id = template_id;
	}
	public String getUrl() {
		return url;
	}
	public void setUrl(String url) {
		this.url = url;
	}
	public Map<String, String> getMiniprogram() {
		return miniprogram;
	}
	public void setMiniprogram(Map<String, String> miniprogram) {
		this.miniprogram = miniprogram;
	}
	public TreeMap<String, TreeMap<String, String>> getData() {
		return data;
	}
	public void setData(TreeMap<String, TreeMap<String, String>> data) {
		this.data = data;
	} 
	
	 /** 
     * 参数 
     * @param value 
     * @param color 可不填 
     * @return 
     */  
    public static TreeMap<String, String> item(String value, String color) {  
        TreeMap<String, String> params = new TreeMap<String, String>();  
        params.put("value", value);  
        params.put("color", color);  
        return params;  
    } 
}
