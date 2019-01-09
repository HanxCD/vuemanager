package com.local.vm.service;


import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.local.vm.mapper.RoleMapper;
import com.local.vm.model.Role;

/**
* Copyright (C),2017, Guangzhou sys info. Co., Ltd.
* @ClassName: RoleService  
* @Description: 角色管理 Service
* @author lao  
* @date 2018年1月4日下午1:56:45  
* @version 1.00
 */
@Service
public class RoleService extends BaseService<Role> {

	@Resource
	RoleMapper roleMapper;

	Map<String,Long> map = new HashMap<String,Long>();
	
	/**
	* @Description: 分页查询
	* @param currPage
	* @param pageSize
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月4日下午1:59:20
	* @version 1.00
	 */
	public List<Role> selectByPage(Long currPage,Long pageSize){
		map.put("currPage", currPage);
		map.put("pageSize", pageSize);
		return roleMapper.selectByPage(map);
	}

	/**
	* @Description: 查询总数
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月4日下午1:59:02
	* @version 1.00
	 */
	public Long selectCount(){
		return roleMapper.selectCount();
	}
	
}
