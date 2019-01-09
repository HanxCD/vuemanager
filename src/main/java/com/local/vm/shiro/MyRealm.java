package com.local.vm.shiro;

import com.local.vm.model.AdminUser;
import com.local.vm.service.AdminUserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.annotation.Resource;

/*
 * shiro认证 + 授权
 */
public class MyRealm extends AuthorizingRealm {

    @Resource
    AdminUserService adminUserService;

    /*
    *  授权 Realm
    */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String account = (String) principalCollection.getPrimaryPrincipal();
        AdminUser pojo = new AdminUser();
        pojo.setAccount(account);
        Long userId = adminUserService.selectOne(pojo).getId();

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        /** 根据用户查询角色role，放入Authorization里 **/
        info.setRoles(adminUserService.findRoleByUserId(userId));
        /** 根据用户id查询角色权限permission，放入Authorization里 **/
        info.setStringPermissions(adminUserService.findPermissionByUserId(userId));
        return info;
    }

    /**
     *
     * 登录认证 realm
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
        String password = (String) token.getCredentials();
        AdminUser user = adminUserService.login(username, password);

        if (null == user){
            throw new AccountException("用户名或密码不正确！");
        }

        if (user.getIsDisabled()){
            throw new DisabledAccountException("用户已禁止登录！");
        }

        //**密码校验**交给AuthenticatingRealm使用CredentialsMatcher进行密码匹配
        return new SimpleAuthenticationInfo(user.getAccount(),user.getPassword(), ByteSource.Util.bytes("3.14159"), getName());
    }

    /**
     * 清空当前用户权限信息
     */
    public  void clearCachedAuthorizationInfo() {
        PrincipalCollection principalCollection = SecurityUtils.getSubject().getPrincipals();
        SimplePrincipalCollection principals = new SimplePrincipalCollection(
                principalCollection, getName());
        super.clearCachedAuthorizationInfo(principals);
    }
    /**
     * 指定principalCollection 清除
     */
    public void clearCachedAuthorizationInfo(PrincipalCollection principalCollection) {
        SimplePrincipalCollection principals = new SimplePrincipalCollection(
                principalCollection, getName());
        super.clearCachedAuthorizationInfo(principals);
    }
}
