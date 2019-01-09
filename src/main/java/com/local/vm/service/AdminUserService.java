package com.local.vm.service;


import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.local.vm.mapper.AdminUserMapper;
import com.local.vm.model.AdminUser;
import com.local.vm.model.AdminUserRoles;

/**
* Copyright (C),2017, Guangzhou sys info. Co., Ltd.
* @ClassName: AdminUserService  
* @Description: 管理员用户管理Service 
* @author lao  
* @date 2018年1月3日上午9:54:56  
* @version 1.00
 */
@Service
public class AdminUserService extends BaseService<AdminUser> {

	@Resource
	AdminUserMapper adminUserMapper;
	
	Map<String,Long> map = new HashMap<String,Long>();

	/**
	* @Description: 登录认证
	* @param account
	* @param password
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月2日上午11:09:40
	* @version 1.00
	 */
	public AdminUser login(String account,String password) {
		AdminUser adminUser= new AdminUser();
		adminUser.setAccount(account);
		adminUser.setPassword(password);
		return adminUserMapper.login(adminUser);
	}

	/**
	* @Description: 分页查询
	* @param currPage
	* @param pageSize
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月3日上午10:01:35
	* @version 1.00
	 */
	public List<AdminUser> selectByPage(Long currPage,Long pageSize){
		map.put("currPage", currPage);
		map.put("pageSize", pageSize);
		return adminUserMapper.selectByPage(map);
	}
	
	/**
	* @Description: 查询总数
	* @return Long
	* @throws  
	* @author lao
	* @Date 2018年1月3日上午10:01:55
	* @version 1.00
	 */
	public Long selectCount(){
		return adminUserMapper.selectCount();
	}
	
	/**
	* @Description: 删除管理员用户和角色关联
	* @param adminUserId
	* @param roleId
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月3日下午2:13:06
	* @version 1.00
	 */
	public Boolean delAdminUserRole(Long adminUserId,Long roleId) throws RuntimeException{
		AdminUserRoles aur = new AdminUserRoles();
		if(adminUserId!=null){
			aur.setAdminUserId(adminUserId);
		}
		if(roleId!=null){
			aur.setRoleId(roleId);
		}
		return adminUserMapper.delAdminUserRole(aur);
	}
	
	/**
	* @Description: 添加管理员用户和角色关联
	* @param adminUserId
	* @param roleId
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月8日下午3:44:56
	* @version 1.00
	 */
	public Boolean addAdminUserRole(Long adminUserId,Long roleId) throws RuntimeException{
		AdminUserRoles aur = new AdminUserRoles();
		aur.setAdminUserId(adminUserId);
		aur.setRoleId(roleId);
		return adminUserMapper.addAdminUserRole(aur);
	}	
	
	/**
	* @Description: 查询管理员用户和角色关联
	* @param adminUserId
	* @param roleId
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月8日下午3:45:21
	* @version 1.00
	 */
	public List<AdminUserRoles> selectAdminUserRole(Long adminUserId,Long roleId){
		AdminUserRoles aur = new AdminUserRoles();
		if(adminUserId!=null){
			aur.setAdminUserId(adminUserId);
		}
		if(roleId!=null){
			aur.setRoleId(roleId);
		}
		return adminUserMapper.selectAdminUserRole(aur);
	}	
	
	/**
	* @Description: 禁用/启用
	* @param id
	* @param isDisabled
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月9日上午10:13:03
	* @version 1.00
	 */
	public Boolean updateDisabled(Long id,boolean isDisabled){
		AdminUser adminUser= new AdminUser();
		adminUser.setId(id);
		adminUser.setIsDisabled(isDisabled);
		return adminUserMapper.updateDisabled(adminUser);
	}

	/**
	* @Description: 根据用户ID查询角色
	* @param adminUserId
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月10日下午5:12:02
	* @version 1.00
	 */
	public Set<String> findRoleByUserId(Long adminUserId){
		return adminUserMapper.findRoleByUserId(adminUserId);
	}
	
	/**
	* @Description: 根据用户ID查询权限
	* @param adminUserId
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月10日下午5:12:09
	* @version 1.00
	 */
	public Set<String> findPermissionByUserId(Long adminUserId){
		return adminUserMapper.findPermissionByUserId(adminUserId);
	}
	
	
}
