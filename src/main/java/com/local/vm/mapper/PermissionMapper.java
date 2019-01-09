package com.local.vm.mapper;

import java.util.List;
import java.util.Map;

import com.local.vm.model.Permission;
import com.local.vm.model.RolePermissions;

/**
* Copyright (C),2017, Guangzhou ChangLing info. Co., Ltd.
* @ClassName: PermissionMapper  
* @Description: TODO 
* @author lao  
* @date 2018年1月3日下午3:40:56  
* @version 1.00
 */
public interface PermissionMapper extends IMapper<Permission> {

	/**
	* @Description: 删除角色和权限关联
	* @param rp
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月3日下午3:41:59
	* @version 1.00
	 */
	Boolean delRolePermission(RolePermissions rp);
	
	/**
	* @Description: 添加角色和权限关联
	* @param rp
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月4日下午3:29:16
	* @version 1.00
	 */
	Boolean addRolePermission(RolePermissions rp);

	/**
	* @Description: 分页查询
	* @param map
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月3日下午3:56:46
	* @version 1.00
	 */
	List<Permission> selectByPage(Map<String, Long> map);
	
	/**
	* @Description: 查询总数
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月3日下午3:57:17
	* @version 1.00
	 */
	Long selectCount();
	
	/**
	* @Description: 查询角色和权限关联
	* @param rp
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月5日下午2:42:29
	* @version 1.00
	 */
	List<RolePermissions> selectRolePermission(RolePermissions rp);
	
}
