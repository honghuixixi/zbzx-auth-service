package com.aek56.microservice.auth.exception;

import java.util.Locale;
import java.util.ResourceBundle;

/**
 * 异常配置信息加载
 *	
 * @author HongHui
 * @date   2017年9月30日
 */
public class ExceptionResources {

    public static String getErrorMessage(String key, Object... params) {
    	try{
    		ResourceBundle resourceBundleError = ResourceBundle.getBundle("i18n/errors", Locale.SIMPLIFIED_CHINESE);
            if (params != null && params.length > 0) {
                return String.format(resourceBundleError.getString(key), params);
            }
            return resourceBundleError.getString(key);
    	}catch(Exception e){
    		e.printStackTrace();
    		return "服务器内部错误";
    	}
    }

}
