package com.cxtx.uaa.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;
import java.util.Arrays;

/**
 * oauth 是一个开放授权标准协议，用于用户授权第三方应用访问其他服务资源
 * 例：微信登录其他平台，第三方（客户端），服务资源（微信）；流程：用户登录客户端，通过微信扫码，授权后，微信发给客户端一个授权码，客户端通过授权吗请求令牌，微信发放令牌，平台通过令牌获取微信上用户信息完成注册
 * 授权服务配置
 * @EnableAuthorizationServer 标记这是一个oauth2.0授权服务
 * oauth 4个角色 客户端（client_id,client_secret）,资源拥有者，授权服务器（要同时校验客户端和资源服务后才给客户端发授权吗），资源服务器
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private ClientDetailsService clientDetailsService;

    //使用授权吗模式，要用授权码服务
    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;

    //认证管理器
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtAccessTokenConverter accessTokenConverter;

    @Autowired
    PasswordEncoder passwordEncoder;

    /**
     * 配置客户端,将客户端信息存到数据库，表oauth_client_details
     * @param dataSource
     * @return
     */
    @Bean
    public ClientDetailsService clientDetailsService(DataSource dataSource){
        ClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        ((JdbcClientDetailsService)clientDetailsService).setPasswordEncoder(passwordEncoder); //密码格式
        return clientDetailsService;
    }
    //授权-> 给客户端 -> 发token ->前提暴露端点url -> 配置token如何存储，token管理服务 -> 给端点url配安全约束

    /**
     * 授权吗模式-最安全的：浏览器http://localhost:7003/uaa/oauth/authorize?client_id=c1&response_type=code&scope=all&redirect_uri=http://www.baidu.com 获取授权码 ->
     *                  跳转到授权页面 -> 返回授权吗 -> postman post oauth/token form参数 client_id=c1，client_secret=secret，grant_type=authorization_code，code=，redirect_uri=http://www.baidu.com -> 获取token
     * 简单模式：浏览器http://localhost:7003/uaa/oauth/authorize?client_id=c1&response_type=token&scope=all&redirect_uri=http://www.baidu.com -> 授权页面 ->返回token
     * 密码模式-适用于我们自己开发的前端：postman post  oauth/token form参数 client_id=c1，client_secret=secret，grant_type=password，username=zhangsan，password=123
     * 客户端模式 对客户端很信任：postman post  oauth/token form参数 client_id=c1，client_secret=secret，grant_type=client_credentials
     *
     *
     *
     *
     *
     * 第一项，配置客户端详情
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //数据库模式
        clients.withClientDetails(clientDetailsService);
    }

    /**
     * 第二项，暴露令牌访问端点url
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager) //密码模式需要
                .authorizationCodeServices(authorizationCodeServices) //授权码模式需要
                .tokenServices(tokenServices()) //令牌管理服务
                .allowedTokenEndpointRequestMethods(HttpMethod.POST); //允许post提交访问端点
    }

    /**
     * 第二项，令牌访问服务
     * @return
     */
    @Bean
    public AuthorizationServerTokenServices tokenServices(){
        DefaultTokenServices services = new DefaultTokenServices();
        services.setClientDetailsService(clientDetailsService); //客户端消息服务
        services.setSupportRefreshToken(true); //是否产生刷新令牌
        services.setTokenStore(tokenStore); //令牌存储策略
        //设置令牌增强
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(accessTokenConverter));
        services.setTokenEnhancer(tokenEnhancerChain);

        services.setAccessTokenValiditySeconds(7200);//令牌默认有效期2小时
        services.setRefreshTokenValiditySeconds(259200); //刷新令牌有效期3天
        return services;
    }


    //配置授权吗模式的授权码数据库中
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(DataSource dataSource){
        return new JdbcAuthorizationCodeServices(dataSource);
    }



    /**
     * 第三项，令牌访问端点的安全策略
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()") // oauth/token_key 公开
                .checkTokenAccess("permitAll()") // oauth/check_token 公开  校验令牌的端点
                .allowFormAuthenticationForClients();//允许表单认证，申请令牌
    }




}
