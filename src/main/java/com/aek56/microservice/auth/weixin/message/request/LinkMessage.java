package com.aek56.microservice.auth.weixin.message.request;

/**
 * 请求消息之链接消息
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class LinkMessage extends BaseMessage {
	
	// 消息标题
    private String Title;
    // 消息描述
    private String Description;
    // 消息链接
    private String Url;

    public String getTitle() {
        return Title;
    }

    public void setTitle(String title) {
        Title = title;
    }

    public String getDescription() {
        return Description;
    }

    public void setDescription(String description) {
        Description = description;
    }

    public String getUrl() {
        return Url;
    }

    public void setUrl(String url) {
        Url = url;
    }
}
