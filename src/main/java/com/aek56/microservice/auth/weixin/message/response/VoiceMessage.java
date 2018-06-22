package com.aek56.microservice.auth.weixin.message.response;

/**
 * 语音
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class VoiceMessage extends BaseMessage {
	// 语音
    private Voice Voice;

	public Voice getVoice() {
		return Voice;
	}

	public void setVoice(Voice voice) {
		Voice = voice;
	}
    
}
