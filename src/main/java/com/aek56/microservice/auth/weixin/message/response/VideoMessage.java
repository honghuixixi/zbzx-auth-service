package com.aek56.microservice.auth.weixin.message.response;

/**
 * 文本消息
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class VideoMessage extends BaseMessage {
	// 视频
    private Video Video;

    public Video getVideo() {
        return Video;
    }

    public void setVideo(Video video) {
        Video = video;
    }
}
