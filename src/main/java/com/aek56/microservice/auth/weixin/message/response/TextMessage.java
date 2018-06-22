package com.aek56.microservice.auth.weixin.message.response;

/**
 * 文本消息
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class TextMessage extends BaseMessage {
	// 回复的消息内容
    private String Content;

    public String getContent() {
        return Content;
    }

    public void setContent(String content) {
        Content = content;
    }
}
