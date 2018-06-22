package com.aek56.microservice.auth.weixin.message.response;

/**
 * 回复的语音消息
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class Voice {
	 // 媒体文件id
    private String MediaId;

    public String getMediaId() {
        return MediaId;
    }

    public void setMediaId(String mediaId) {
        MediaId = mediaId;
    }
}
