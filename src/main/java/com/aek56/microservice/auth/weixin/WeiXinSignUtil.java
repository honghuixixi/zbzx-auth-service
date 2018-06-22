package com.aek56.microservice.auth.weixin;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * 微信请求验证工具
 *	
 * @author HongHui
 * @date   2017年11月29日
 */
public class WeiXinSignUtil {
	
	/**
	 * 验证签名
	 * @param signature
	 * @param timestamp
	 * @param nonce
	 * @return
	 */
	public static boolean checkSignature(String token,String signature,String timestamp,String nonce){
		String sign = null;
		try {
			String[] params = new String[] { token, timestamp, nonce};
			//将token,timestamp,nonce三个参数进行字典排序
			Arrays.sort(params);
			StringBuilder content = new StringBuilder();
			for (String param : params) {
				content.append(param);
			}
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
			byte[] digest = messageDigest.digest(content.toString().getBytes());
			sign = byteToStr(digest);
			content = null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		//将sha1加密后的字符串可与signature对比，标识该请求来源于微信
		return sign != null ? sign.equals(signature.toUpperCase()) : false;
	}
	
	/**
	 * 将字节数组转换为十六进制字符
	 * @param byteArray
	 * @return
	 */
	 public static String byteToStr(byte[] byteArray) {  
		String strDigest = "";  
		for (int i = 0; i < byteArray.length; i++) {  
		    strDigest += byteToHexStr(byteArray[i]);  
		}  
		return strDigest;  
	 }
	 
	 /**
	  * 将字节转换为十六进制字符
	  * @param mByte
	  * @return
	  */
	 private static String byteToHexStr(byte mByte) {  
		char[] Digit = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };  
        char[] tempArr = new char[2];  
        tempArr[0] = Digit[(mByte >>> 4) & 0X0F];  
        tempArr[1] = Digit[mByte & 0X0F];  
  
        String s = new String(tempArr);  
        return s;  
	} 
	
}
