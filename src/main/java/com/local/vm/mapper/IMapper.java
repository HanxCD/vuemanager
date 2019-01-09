package com.local.vm.mapper;

import java.util.List;

/**

* Copyright (C),2017, Guangzhou ChangLing info. Co., Ltd.

* FileName: IMapper.java

* 父接口

* @author hey
    * @Date    2017年12月1日 下午1:49:37

* @version 1.00

*/
public interface IMapper<T> {
	int insert(T pojo);
	
	/**
	* 根据id进行更新
	* @param pojo
	* @return 返回更新的列数
	* @author hey
	* @version 1.00
	*/
	int update(T pojo);

	/**
	* 根据id删除数据
	* @param id 数据的id值
	* @return 返回删除的数据条数
	* @author hey
	* @version 1.00
	*/
	int delete(Long id);
	
	/**
	* 以非空字段值作为查询条件进行查询
	* @param pojo
	* @return 查询到的结果集，以集合形式返回
	* @author hey
	* @version 1.00
	*/
	List<T> select(T pojo);
}
