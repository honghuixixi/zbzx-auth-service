package com.aek56.microservice.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;

import feign.codec.Encoder;
import feign.form.spring.SpringFormEncoder;

/**
 * 
 *
 * @author  Honghui
 * @date    2018年3月1日
 * @version 1.0
 */
@Configuration
public class FeignMultipartSupportConfig {

	@Bean
    @Primary
    @Scope("prototype")
    public Encoder multipartFormEncoder() {
        return new SpringFormEncoder();
    }

    @Bean
    public feign.Logger.Level multipartLoggerLevel() {
        return feign.Logger.Level.FULL;
    }
}
