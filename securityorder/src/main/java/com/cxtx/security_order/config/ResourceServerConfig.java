package com.cxtx.security_order.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer  //标记这是个资源服务
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    public static final String RESOURCE_ID = "res1";

    @Autowired
    TokenStore tokenStore;

    /**
     * 本地校验token
     * http://localhost:7003/uaa/oauth/check_token   header token=
     * {
     *   "aud": [
     *     "res2"
     *   ],
     *   "user_name": "zhangsan",
     *   "scope": [
     *     "ROLE_USER",
     *     "ROLE_API"
     *   ],
     *   "exp": 1620795644,
     *   "authorities": [
     *     "p1"
     *   ],
     *   "jti": "9ee08cc4-58da-422d-8d33-c04e3cfe4e3b",
     *   "client_id": "c2"
     * }
     * @param resources
     * @throws Exception
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId(RESOURCE_ID) //资源id  访问此服务的客户端aud必须包含res1权限才能访问此服务
                .tokenStore(tokenStore)
                .stateless(true);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/**").access("#oauth2.hasScope('ROLE_ADMIN')")
                //申请的客户端必须带有ROLE_ADMIN授权范围，才能访问res1资源下的/** 资源
                .and().csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

}
