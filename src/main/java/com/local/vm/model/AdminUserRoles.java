/**
 * 
 */
package com.local.vm.model;

import java.io.Serializable;

/**  
* Copyright (C),2017, Guangzhou ChangLing info. Co., Ltd.
* @ClassName: AdminUserRoles  
* @Description: 用户角色关联表 
* @author lao  
* @date 2017年12月27日上午10:14:15  
* @version 1.00 
*/
public class AdminUserRoles implements Serializable {

	private static final long serialVersionUID = 1L;

	/** 外键表，指向管理员用户表  */
	private Long adminUserId;
	/** 外键表，指向角色表 */
	private Long roleId;
	
	
	public Long getAdminUserId() {
		return adminUserId;
	}
	public void setAdminUserId(Long adminUserId) {
		this.adminUserId = adminUserId;
	}
	public Long getRoleId() {
		return roleId;
	}
	public void setRoleId(Long roleId) {
		this.roleId = roleId;
	}
	public static long getSerialversionuid() {
		return serialVersionUID;
	}
	
}
