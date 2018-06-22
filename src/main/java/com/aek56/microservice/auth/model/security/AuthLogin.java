package com.aek56.microservice.auth.model.security;

public class AuthLogin
{
    /**
     * 设备类型
     */
    private String deviceType;
    
    /**
     * 设备Id
     */
    private String deviceId;
    
    /**
     * 登录账户
     */
    private String loginName;
    
    /**
     * 机构Id
     */
    private String tenantId;
    
    public String getDeviceType()
    {
        return deviceType;
    }
    
    public void setDeviceType(String deviceType)
    {
        this.deviceType = deviceType;
    }
    
    public String getDeviceId()
    {
        return deviceId;
    }
    
    public void setDeviceId(String deviceId)
    {
        this.deviceId = deviceId;
    }
    
    public String getLoginName()
    {
        return loginName;
    }
    
    public void setLoginName(String loginName)
    {
        this.loginName = loginName;
    }
    
    public String getTenantId()
    {
        return tenantId;
    }
    
    public void setTenantId(String tenantId)
    {
        this.tenantId = tenantId;
    }
    
}
