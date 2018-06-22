package com.aek56.microservice.auth.weixin.message.event;

/**
 * 扫描带参数二维码事件
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class QRCodeEvent extends BaseEvent {
	
	// 事件KEY值
    private String EventKey;
    // 用于换取二维码图片
    private String Ticket;

    public String getEventKey() {
        return EventKey;
    }

    public void setEventKey(String eventKey) {
        EventKey = eventKey;
    }

    public String getTicket() {
        return Ticket;
    }

    public void setTicket(String ticket) {
        Ticket = ticket;
    }
}
