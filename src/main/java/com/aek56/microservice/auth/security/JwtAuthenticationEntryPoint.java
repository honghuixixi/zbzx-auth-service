package com.aek56.microservice.auth.security;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.google.gson.Gson;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

    private static final long serialVersionUID = -8970718410437077606L;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
    	response.setContentType("application/json;charset=utf-8");
    	Map<String,String> retVal = new HashMap<>();
    	retVal.put("code", "401");
    	retVal.put("msg", "未登录.");
    	Gson gson = new Gson();
    	String json = gson.toJson(retVal);
    	response.getOutputStream().write(json.getBytes("UTF-8"));
    }
}