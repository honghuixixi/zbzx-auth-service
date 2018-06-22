package com.aek56.microservice.auth.apis;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.aek56.microservice.auth.exception.UserNotExistException;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

@ControllerAdvice
public class MyExceptionHandler {
	private static final Log logger = LogFactory.getLog(MyExceptionHandler.class);

	/** 异常处理 */
	@ExceptionHandler(Exception.class)
	public void exceptionHandler(HttpServletRequest request, HttpServletResponse response, Exception ex) {
		try {
			Map<String,Object> map = new HashMap<String,Object>();
			if(ex instanceof HttpRequestMethodNotSupportedException){
				map.put("code", 405);
				map.put("msg", ex.getMessage());
			}else if(ex.getCause()!=null && ex.getCause() instanceof UserNotExistException){
				map.put("code", 411);
				map.put("msg", "用户不存在.");
			}else if(ex instanceof BadCredentialsException){
				map.put("code", 406);
				map.put("msg", "密码错误.");
			}else if(ex instanceof AccessDeniedException){
				map.put("code", "403");
				map.put("msg", "没权限.");
			}else{
				map.put("code", 500);
				map.put("msg", "System Internal Error");
                logger.error("System Internal Error.", ex);
			}
			logger.info("异常返回信息=" + map);
			response.setContentType("application/json;charset=UTF-8");
			ServletOutputStream servletOutputStream = response.getOutputStream();
			byte[] bytes = JSON.toJSONBytes(map , SerializerFeature.DisableCircularReferenceDetect);
			servletOutputStream.write(bytes);
		} catch (IOException e) {
			logger.error("Output Error.", e);
		}
	}
}

