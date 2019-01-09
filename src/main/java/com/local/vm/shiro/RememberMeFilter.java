/**
 * 
 */
package com.local.vm.shiro;

import javax.annotation.Resource;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;

import com.local.vm.model.AdminUser;
import com.local.vm.service.AdminUserService;


/**  
* Copyright (C),2017, Guangzhou sys info. Co., Ltd.
* @ClassName: RememberMeFilter  
* @Description: 实现RememberMe过滤器
* @author lao  
* @date 2018年1月12日上午11:58:40  
* @version 1.00 
*/
public class RememberMeFilter extends FormAuthenticationFilter {
	protected final static Logger logger = LogManager.getLogger(RememberMeFilter.class);
	
	@Resource
	private AdminUserService adminUserService;
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request,ServletResponse response,Object mappedValue){
		Subject subject = getSubject(request,response);
		Session session = subject.getSession();
		/**满足三个条件：选择记住我,非密码登录,session为空*/
		if(!subject.isAuthenticated() && subject.isRemembered() && session.getAttribute("user") == null){
			Object principal = subject.getPrincipal();
			if(principal!=null){
				AdminUser pojo = new AdminUser();
				pojo.setAccount(principal.toString());
				AdminUser user = adminUserService.selectOne(pojo);
				session.setAttribute("user", user.getAccount());
			}
		}
		return subject.isAuthenticated()||subject.isRemembered();
	}
	
	
}
