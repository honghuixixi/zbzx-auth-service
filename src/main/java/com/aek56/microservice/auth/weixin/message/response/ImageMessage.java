package com.aek56.microservice.auth.weixin.message.response;

/**
 * 图片消息
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class ImageMessage extends BaseMessage {
    
    private Image Image;

    public Image getImage() {
        return Image;
    }

    public void setImage(Image image) {
        Image = image;
    }
}
