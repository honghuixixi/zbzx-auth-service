package com.aek56.microservice.auth.common;

/**
 * 常量表
 */
public interface Constants {
    /**
     * 未知错误
     */
    public static final String EXCEPTION_HEAD = "Server internal error occurred.";
    /** 客户端语言 */
    public static final String USERLANGUAGE = "userLanguage";
    /** 客户端主题 */
    public static final String WEBTHEME = "webTheme";
    /** 在线用户数量 */
    public static final String ALLUSER_NUMBER = "ALLUSER_NUMBER";
    /** 登录用户数量 */
    public static final String USER_NUMBER = "USER_NUMBER";
    /** 上次请求地址 */
    public static final String PREREQUEST = "PREREQUEST";
    /** 上次请求时间 */
    public static final String PREREQUEST_TIME = "PREREQUEST_TIME";
    /** 非法请求次数 */
    public static final String MALICIOUS_REQUEST_TIMES = "MALICIOUS_REQUEST_TIMES";
    /** 缓存命名空间 */
    public static final String CACHE_NAMESPACE = "aek:";
    
    
    /*----------------------session缓存--------------------------------------------------*/
    /** 当前用户 */
    public static final String CURRENT_USER = "CURRENT_USER";
    /** 验证码缓存 */
    public static final String LOGIN_CHECK_CODE = "LOGIN_CHECK_CODE";
    /** 用户权限*/
    public static final String CURRENT_USER_PERMS = "CURRENT_USER_PERMS";
    /** 用户登录次数 登录5次需要验证码*/
    public static final String USER_LOGIN_TIMES = "USER_LOGIN_TIMES";
    
    /** 日志表状态 */
    public interface JOBSTATE {
        /**
         * 日志表状态，初始状态，插入
         */
        public static final String INIT_STATS = "I";
        /**
         * 日志表状态，成功
         */
        public static final String SUCCESS_STATS = "S";
        /**
         * 日志表状态，失败
         */
        public static final String ERROR_STATS = "E";
        /**
         * 日志表状态，未执行
         */
        public static final String UN_STATS = "N";
    }
}
