package com.aek56.microservice.auth.weixin.request;

import java.io.Serializable;

import org.hibernate.validator.constraints.NotEmpty;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * 微信公众号发送维修消息请求实体类
 *	
 * @author HongHui
 * @date   2017年12月5日
 */
@ApiModel(value = "WeiXinRepairMessageRequest", description = "维修消息推送")
public class  WeiXinRepairMessageRequest implements Serializable {

	private static final long serialVersionUID = 2715780059307779372L;

	//机构ID
	@ApiModelProperty(value = "机构ID")
    @NotEmpty
    private Long tenantId;
  	//维修申请单ID
	@ApiModelProperty(value = "维修申请单ID")
    @NotEmpty
  	private Long applyId;
  	//维修消息类型1=接单，2=维修,3=验收
	@ApiModelProperty(value = "维修消息类型1=接单，2=维修,3=验收")
    @NotEmpty
  	private Integer type;
  	//维修申请号
	@ApiModelProperty(value = "维修申请单号")
    @NotEmpty
  	private String applyNo;
  	//设备名称
	@ApiModelProperty(value = "设备名称")
    @NotEmpty
  	private String assetsName;
  	//设备编号
	@ApiModelProperty(value = "设备编号")
    @NotEmpty
  	private String assetsNum;
  	//设备使用部门id
	@ApiModelProperty(value = "设备使用部门id")
    @NotEmpty
  	private Long assetsDeptId;
  	//设备使用科室名称
	@ApiModelProperty(value = "设备使用科室名称")
    @NotEmpty
  	private String assetsDeptName;
  	//申请人ID
	@ApiModelProperty(value = "申请人ID")
    @NotEmpty
  	private Long reportRepairId;
  	//申请人姓名
	@ApiModelProperty(value = "申请人姓名")
    @NotEmpty
  	private String reportRepairName;

	public Long getTenantId() {
		return tenantId;
	}

	public void setTenantId(Long tenantId) {
		this.tenantId = tenantId;
	}

	public Long getApplyId() {
		return applyId;
	}

	public void setApplyId(Long applyId) {
		this.applyId = applyId;
	}

	public Integer getType() {
		return type;
	}

	public void setType(Integer type) {
		this.type = type;
	}

	public String getApplyNo() {
		return applyNo;
	}

	public void setApplyNo(String applyNo) {
		this.applyNo = applyNo;
	}

	public String getAssetsName() {
		return assetsName;
	}

	public void setAssetsName(String assetsName) {
		this.assetsName = assetsName;
	}

	public String getAssetsNum() {
		return assetsNum;
	}

	public void setAssetsNum(String assetsNum) {
		this.assetsNum = assetsNum;
	}

	public Long getAssetsDeptId() {
		return assetsDeptId;
	}

	public void setAssetsDeptId(Long assetsDeptId) {
		this.assetsDeptId = assetsDeptId;
	}

	public String getAssetsDeptName() {
		return assetsDeptName;
	}

	public void setAssetsDeptName(String assetsDeptName) {
		this.assetsDeptName = assetsDeptName;
	}

	public Long getReportRepairId() {
		return reportRepairId;
	}

	public void setReportRepairId(Long reportRepairId) {
		this.reportRepairId = reportRepairId;
	}

	public String getReportRepairName() {
		return reportRepairName;
	}

	public void setReportRepairName(String reportRepairName) {
		this.reportRepairName = reportRepairName;
	}

}
