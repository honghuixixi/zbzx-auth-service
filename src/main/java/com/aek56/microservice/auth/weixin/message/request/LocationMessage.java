package com.aek56.microservice.auth.weixin.message.request;

/**
 * 请求消息之视频消息
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class LocationMessage extends BaseMessage {
	
	// 媒体ID
    private String MediaId;
    // 语音格式
    private String ThumbMediaId;

    public String getMediaId() {
        return MediaId;
    }
    public void setMediaId(String mediaId) {
        MediaId = mediaId;
    }
    public String getThumbMediaId() {
        return ThumbMediaId;
    }
    public void setThumbMediaId(String thumbMediaId) {
        ThumbMediaId = thumbMediaId;
    }
}
