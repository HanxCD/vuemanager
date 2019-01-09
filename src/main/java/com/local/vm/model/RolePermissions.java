package com.local.vm.model;

import java.io.Serializable;

/**
* Copyright (C),2017, Guangzhou ChangLing info. Co., Ltd.
* @ClassName: RolePermissions  
* @Description: 角色权限关联表 
* @author lao  
* @date 2017年12月27日上午10:17:04  
* @version 1.00
*/
public class RolePermissions implements Serializable {

	private static final long serialVersionUID = 1L;
	
	/** 外键表，指向角色表  */
	private Long roleId;
	/** 外键表，指向权限表 */
	private Long permissionId;
	
	public Long getRoleId() {
		return roleId;
	}
	public void setRoleId(Long roleId) {
		this.roleId = roleId;
	}
	public Long getPermissionId() {
		return permissionId;
	}
	public void setPermissionId(Long permissionId) {
		this.permissionId = permissionId;
	}
	public static long getSerialversionuid() {
		return serialVersionUID;
	}
	
	
	
}
