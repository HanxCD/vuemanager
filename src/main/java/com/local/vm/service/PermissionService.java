package com.local.vm.service;


import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.local.vm.mapper.PermissionMapper;
import com.local.vm.model.Permission;
import com.local.vm.model.RolePermissions;

/**
* Copyright (C),2017, Guangzhou sys info. Co., Ltd.
* @ClassName: PermissionService  
* @Description: 权限管理 Service
* @author lao  
* @date 2018年1月3日下午3:43:05  
* @version 1.00
 */
@Service
public class PermissionService extends BaseService<Permission> {

	@Resource
	PermissionMapper permissionMapper;
	
	Map<String,Long> map = new HashMap<String,Long>();
	
	/**
	* @Description: 删除角色和权限关联
	* @param roleId
	* @param permissionId
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月3日下午3:47:28
	* @version 1.00
	 */
	public Boolean delRolePermission(Long roleId,Long permissionId){
		RolePermissions rp = new RolePermissions();
		if(roleId!=null){
			rp.setRoleId(roleId);
		}
		if(permissionId!=null){
			rp.setPermissionId(permissionId);
		}
		return permissionMapper.delRolePermission(rp);
	}
	
	/**
	* @Description: 添加角色和权限关联
	* @param roleId
	* @param permissionId
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月4日下午3:31:35
	* @version 1.00
	 */
	public Boolean addRolePermission(Long roleId,Long permissionId){
		RolePermissions rp = new RolePermissions();
		if(roleId!=null&&permissionId!=null){
			rp.setRoleId(roleId);
			rp.setPermissionId(permissionId);
		}
		return permissionMapper.addRolePermission(rp);
	}
	
	/**
	* @Description: 分页查询
	* @param currPage
	* @param pageSize
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月3日下午4:00:45
	* @version 1.00
	 */
	public List<Permission> selectByPage(Long currPage,Long pageSize){
		map.put("currPage", currPage);
		map.put("pageSize", pageSize);
		return permissionMapper.selectByPage(map);
	}
	
	/**
	* @Description: 查询总数
	* @return Long
	* @throws  
	* @author lao
	* @Date 2018年1月3日下午4:01:39
	* @version 1.00
	 */
	public Long selectCount(){
		return permissionMapper.selectCount();
	}
	
	/**
	* @Description: 查询角色和权限关联
	* @param roleId
	* @param permissionId
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月5日下午2:45:18
	* @version 1.00
	 */
	public List<RolePermissions> selectRolePermission(Long roleId,Long permissionId){
		RolePermissions rp = new RolePermissions();
		if(roleId!=null){
			rp.setRoleId(roleId);
		}
		if(permissionId!=null){
			rp.setPermissionId(permissionId);
		}
		return permissionMapper.selectRolePermission(rp);
	}
	
}
