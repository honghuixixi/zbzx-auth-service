package com.aek56.microservice.auth.util;

import com.aek56.microservice.auth.common.Result;
import com.aek56.microservice.auth.exception.BusinessException;

public final class ResponseUtil {

    private static final String FAULT_CODE = "500";
    private static final String SUCCESS_CODE = "200";
    private static final String N0_PERMS_CODE = "403";

    private static final String SUCCESS_MSG = "OK";
    private static final String FAULT_MSG = "服务器内部错误";
    private static final String UNKNOWN_MSG = "服务器内部未知错误";
    private static final String N0_PERMS = "没有相关操作权限";
    

    public static <T> Result<T> getBusinessResult(BusinessException ex){
        return new Result<T>(ex.getXCode(), ex.getMessageWithoutCode());
    }
    
    public static <T> Result<T> getFaultResult() {
        return new Result<T>(FAULT_CODE, FAULT_MSG);
    }

    public static <T> Result<T> getSuccessResult(T obj){
        return new Result<T>(SUCCESS_CODE, SUCCESS_MSG, obj);
    }

    public static <T> Result<T> getUnknownResult(){
        return new Result<T>(FAULT_CODE, UNKNOWN_MSG);
    }
    
    /**
     * 没有权限
     * @return
     */
    public static <T> Result<T> getNotPermsResult(){
    	return new Result<T>(N0_PERMS_CODE, N0_PERMS);
    }
    
    
}
