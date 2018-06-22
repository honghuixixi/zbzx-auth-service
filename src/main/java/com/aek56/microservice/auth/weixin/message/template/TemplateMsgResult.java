package com.aek56.microservice.auth.weixin.message.template;

/**
 * 模板消息 返回的结果
 *	
 * @author HongHui
 * @date   2017年12月4日
 */
public class TemplateMsgResult extends ResultState {

	private static final long serialVersionUID = 5357091510559865334L;

	// 消息id(发送模板消息)  
	private String msgid; 
	  
    public String getMsgid() {  
        return msgid;  
    }  
  
    public void setMsgid(String msgid) {  
        this.msgid = msgid;  
    }

	@Override
	public String toString() {
		return "TemplateMsgResult [msgid=" + msgid + ", toString()=" + super.toString() + "]";
	}  
    
}
