package com.aek56.microservice.auth.weixin.message.event;

/**
 * 自定义菜单事件
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class LocationEvent extends BaseEvent {

	// 事件KEY值，与自定义菜单接口中KEY值对应
    private String EventKey;

    public String getEventKey() {
        return EventKey;
    }

    public void setEventKey(String eventKey) {
        EventKey = eventKey;
    }
}
