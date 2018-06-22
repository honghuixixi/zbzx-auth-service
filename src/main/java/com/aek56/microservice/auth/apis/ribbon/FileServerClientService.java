package com.aek56.microservice.auth.apis.ribbon;

import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;

import com.aek56.microservice.auth.common.Result;
import com.aek56.microservice.auth.config.FeignMultipartSupportConfig;

@FeignClient(value="${feign-fileserver.serviceId}",fallback = FileServerClientHystrix.class,configuration = FeignMultipartSupportConfig.class)
public interface FileServerClientService {

	@RequestMapping(method = RequestMethod.POST, value = "/upload/zbzx4weixin",produces = {MediaType.APPLICATION_JSON_UTF8_VALUE},consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Result<Object> zbzxUploadFile(@RequestPart(value = "file") MultipartFile file);

}
