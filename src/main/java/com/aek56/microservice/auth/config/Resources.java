package com.aek56.microservice.auth.config;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

/**
 * 加载配置
 */
public final class Resources {
    /** 第三方登录配置 */
    public static final ResourceBundle THIRDPARTY = ResourceBundle.getBundle("config/thirdParty");
    /** 国际化信息 */
    private static final Map<String, ResourceBundle> MESSAGES = new HashMap<String, ResourceBundle>();

    private static Locale locale = Locale.SIMPLIFIED_CHINESE;

    private static final ResourceBundle resourceBundle = ResourceBundle.getBundle("i18n/messages", locale);

    private static final ResourceBundle resourceBundleError = ResourceBundle.getBundle("i18n/errors", locale);

    /** 国际化信息 */
    public static String getMessage(String key, Object... params) {
        if (params != null && params.length > 0) {
            return String.format(resourceBundle.getString(key), params);
        }
        return resourceBundle.getString(key);
    }

    public static String getErrorMessage(String key, Object... params) {
        if (params != null && params.length > 0) {
            return String.format(resourceBundleError.getString(key), params);
        }
        return resourceBundleError.getString(key);
    }


    /** 清除国际化信息 */
    public static void flushMessage() {
        MESSAGES.clear();
    }
}
