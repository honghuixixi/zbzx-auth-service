/**
 *
 */
package com.aek56.microservice.auth.common;

import java.io.IOException;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.ValidationException;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindException;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.aek56.microservice.auth.config.Resources;
import com.aek56.microservice.auth.exception.BusinessException;
import com.aek56.microservice.auth.exception.ExceptionFactory;
import com.aek56.microservice.auth.util.ResponseUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.serializer.SerializerFeature;

/**
 * 控制器基类
 */
public abstract class BaseController {
	protected Logger logger = LogManager.getLogger(this.getClass());

	/** 返回成功数据 */
	protected <T> Result<T> response(T data) {
		return ResponseUtil.getSuccessResult(data);
	}

	/**
	 * 返回操作成功
	 * 
	 * @return
	 */
	protected Result<Object> response() {
		return ResponseUtil.getSuccessResult(null);
	}

	/**
	 * 返回值自定义错误消息
	 * 
	 * @return
	 */
	protected Result<Object> responseMsg(String errorCode, Object... args) {
		String msg = Resources.getErrorMessage(errorCode);
		if (args != null && args.length > 0) {
			msg = String.format(msg, args);
		}
		return new Result<Object>("600", msg);
	}

	/** 异常处理 */
	@ExceptionHandler(Exception.class)
	public void exceptionHandler(HttpServletRequest request, HttpServletResponse response, Exception ex) {
		ServletOutputStream servletOutputStream = null;
		Exception e = ex;
		try {
			if (ex instanceof MethodArgumentNotValidException) {
				ObjectError objectError = ((MethodArgumentNotValidException) ex).getBindingResult().getAllErrors().get(0);
				String validationMsg = objectError.getDefaultMessage();
				e = handleErrorMessage(validationMsg);
				logger.error(Constants.EXCEPTION_HEAD, ex);
			} else if (ex instanceof BindException) {
				ObjectError objectError = ((BindException) ex).getBindingResult().getAllErrors().get(0);
				String validationMsg = objectError.getDefaultMessage();
				e = handleErrorMessage(validationMsg);
				logger.error(Constants.EXCEPTION_HEAD, ex);
			}
			/*
			 * else if (ex instanceof UnauthenticatedException) { // 没有登陆 e =
			 * handleErrorMessage("402"); } else if (ex instanceof
			 * UnauthorizedException) { // 没有权限 e = handleErrorMessage("403"); }
			 */ else if (ex instanceof JSONException) {
				// 请求参数JSON参数错误
				e = handleErrorMessage("501");
				logger.error(Constants.EXCEPTION_HEAD, ex);
			} else if (ex instanceof AccessDeniedException) {
				// 没有权限
				e = handleErrorMessage("403");
			} else if (ex instanceof BusinessException) {
				// 自定义异常
				if (ex.getCause() != null) {
					logger.error(ex.getMessage(), ex);
				} else {
					logger.debug(ex.getMessage());
				}
				//e = handleErrorMessage(((BusinessException) ex).getXCode());
				e = (BusinessException)ex;
			} else {
				// 服务器内部错误
				logger.error(Constants.EXCEPTION_HEAD, ex);
			}

			Result<?> result = getFaultResponse(e);
			response.setContentType("application/json;charset=UTF-8");
			servletOutputStream = response.getOutputStream();
			byte[] bytes = JSON.toJSONBytes(result, SerializerFeature.DisableCircularReferenceDetect);
			servletOutputStream.write(bytes);
		} catch (Exception e1) {
			logger.error(e.getMessage(), e1);
		} finally {
			if (servletOutputStream != null) {
				try {
					servletOutputStream.close();
				} catch (IOException e2) {
					logger.error(e2.getMessage(), e2);
				}
			}
		}
	}

	private BusinessException handleErrorMessage(String validationMsg) {
		if (StringUtils.isNotEmpty(validationMsg)) {
			return ExceptionFactory.create(validationMsg);
		}
		String code = "COMMON_1003";
		String errMsg = validationMsg;
		return ExceptionFactory.create(code, errMsg);
	}
	

	private Result<?> getFaultResponse(Exception e) {
		if (e instanceof BusinessException) {
			return ResponseUtil.getBusinessResult((BusinessException) e);
		} else if (e instanceof ValidationException) {
			if (e.getCause() instanceof BusinessException) {
				return ResponseUtil.getBusinessResult(((BusinessException) e.getCause()));
			} else {
				return ResponseUtil.getFaultResult();
			}
		} else if (e instanceof Exception) {
			return ResponseUtil.getFaultResult();
		}
		return ResponseUtil.getUnknownResult();
	}
}
