package com.aek56.microservice.auth.apis.ribbon;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.multipart.MultipartFile;

import com.aek56.microservice.auth.bo.UploadInfo;
import com.aek56.microservice.auth.common.Result;

@Component
public class FileServerClientHystrix implements FileServerClientService {
	
	private static final Logger logger = LogManager.getLogger(FileServerClientHystrix.class);

	@Override
	public Result<Object> zbzxUploadFile(@ModelAttribute MultipartFile file) {
		logger.info("==========================================");
		logger.info("上传文件失败");
		return null;
	}


}
