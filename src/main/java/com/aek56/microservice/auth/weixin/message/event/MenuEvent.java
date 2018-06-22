package com.aek56.microservice.auth.weixin.message.event;

/**
 * 上报地理位置事件
 *	
 * @author HongHui
 * @date   2017年11月30日
 */
public class MenuEvent extends BaseEvent {

	// 地理位置纬度
    private String Latitude;
    // 地理位置经度
    private String Longitude;
    // 地理位置精度
    private String Precision;

    public String getLatitude() {
        return Latitude;
    }

    public void setLatitude(String latitude) {
        Latitude = latitude;
    }

    public String getLongitude() {
        return Longitude;
    }

    public void setLongitude(String longitude) {
        Longitude = longitude;
    }

    public String getPrecision() {
        return Precision;
    }

    public void setPrecision(String precision) {
        Precision = precision;
    }
}
