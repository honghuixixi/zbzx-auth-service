package com.aek56.microservice.auth.weixin.message.response;

/**
 * 音乐
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class MusicMessage extends BaseMessage {
	// 音乐
    private Music Music;

    public Music getMusic() {
        return Music;
    }

    public void setMusic(Music music) {
        Music = music;
    }
    
}
