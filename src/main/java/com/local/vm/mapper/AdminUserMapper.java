package com.local.vm.mapper;

import java.util.List;
import java.util.Map;
import java.util.Set;

import com.local.vm.model.AdminUser;
import com.local.vm.model.AdminUserRoles;

/**
* Copyright (C),2017, Guangzhou ChangLing info. Co., Ltd.
* @ClassName: AdminUserMapper  
* @Description: 管理员用户 
* @author lao  
* @date 2018年1月3日上午9:51:53  
* @version 1.00
 */
public interface AdminUserMapper extends IMapper<AdminUser> {

    /**
    * @Description: 登录认证
    * @param adminUser
    * @return 返回用户详细信息
    * @throws  
    * @author lao
    * @Date 2018年1月3日上午9:52:14
    * @version 1.00
     */
    AdminUser login(AdminUser adminUser);

    /**
    * @Description: 分页查询
    * @param map
    * @return
    * @throws  
    * @author lao
    * @Date 2018年1月3日上午9:53:30
    * @version 1.00
     */
    List<AdminUser> selectByPage(Map<String, Long> map);
    
    /**
    * @Description: 查询总数
    * @return Long
    * @throws  
    * @author lao
    * @Date 2018年1月3日上午9:53:39
    * @version 1.00
     */
    Long selectCount();
    
    /**
    * @Description: 删除管理员用户和角色关联
    * @param aur
    * @return
    * @throws  
    * @author lao
    * @Date 2018年1月3日下午2:05:16
    * @version 1.00
     */
    Boolean delAdminUserRole(AdminUserRoles aur);
    
    /**
    * @Description: 添加管理员用户和角色关联
    * @param aur
    * @return
    * @throws  
    * @author lao
    * @Date 2018年1月8日下午3:41:40
    * @version 1.00
     */
    Boolean addAdminUserRole(AdminUserRoles aur);
    
    /**
    * @Description: 查询管理员用户和角色关联
    * @param aur
    * @return
    * @throws  
    * @author lao
    * @Date 2018年1月8日下午3:42:03
    * @version 1.00
     */
    List<AdminUserRoles> selectAdminUserRole(AdminUserRoles aur);
    
    /**
    * @Description: 禁用/启用
    * @param adminUser
    * @return
    * @throws  
    * @author lao
    * @Date 2018年1月9日上午10:08:36
    * @version 1.00
     */
    Boolean updateDisabled(AdminUser adminUser);
    
    /**
    * @Description: 根据用户ID查询角色
    * @param adminUserId
    * @return
    * @throws  
    * @author lao
    * @Date 2018年1月10日下午5:08:31
    * @version 1.00
     */
    Set<String> findRoleByUserId(Long adminUserId);
    
    /**
    * @Description: 根据用户ID查询权限
    * @param adminUserId
    * @return
    * @throws  
    * @author lao
    * @Date 2018年1月10日下午5:08:41
    * @version 1.00
     */
    Set<String> findPermissionByUserId(Long adminUserId);
    
}
