package com.local.vm.mapper;

import java.util.List;
import java.util.Map;

import com.local.vm.model.Role;

/**
* Copyright (C),2017, Guangzhou ChangLing info. Co., Ltd.
* @ClassName: RoleMapper  
* @Description: TODO 
* @author lao  
* @date 2018年1月4日下午1:54:56  
* @version 1.00
 */
public interface RoleMapper extends IMapper<Role> {

	/**
	* @Description: 分页查询
	* @param map
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月4日下午1:55:07
	* @version 1.00
	 */
	List<Role> selectByPage(Map<String, Long> map);
	
	/**
	* @Description: 查询总数
	* @return
	* @throws  
	* @author lao
	* @Date 2018年1月4日下午1:55:25
	* @version 1.00
	 */
	Long selectCount();
	
}
