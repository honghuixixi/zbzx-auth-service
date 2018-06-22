package com.aek56.microservice.auth.weixin.message.response;

/**
 * 视频
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class Video {
	// 媒体文件id
    private String MediaId;
    // 缩略图的媒体id
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
