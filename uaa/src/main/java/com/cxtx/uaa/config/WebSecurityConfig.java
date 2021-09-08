package com.cxtx.uaa.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true) //security开启方法权限授权注解
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SuccessHandler successHandler;

    @Autowired
    private FailureHandler failureHandler;

    @Autowired
    private LogoutHandler logoutHandler;

    //认证管理器
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return super.authenticationManagerBean();
    }

    /**
     * 密码编码器，对用户密码进行编码
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();  //对用户输入的密码进行编码，然后在与数据库密码比较
    }

    /**
     * 安全拦截机制（最重要）
     *SpringSecurity匹配规则
     * 一 URL匹配
     * requestMatchers() 配置一个request Mather数组，参数为RequestMatcher 对象，其match 规则自定义,需要的时候放在最前面，对需要匹配的的规则进行自定义与过滤
     * authorizeRequests() URL权限配置
     * antMatchers() 配置一个request Mather 的 string数组，参数为 ant 路径格式， 直接匹配url
     * anyRequest 匹配任意url，无参 ,最好放在最后面
     * 二 保护URL
     * authenticated() 保护UrL，需要用户登录
     * permitAll() 指定URL无需保护，一般应用与静态资源文件
     * hasRole(String role) 限制单个角色访问，角色将被增加 “ROLE_” .所以”ADMIN” 将和 “ROLE_ADMIN”进行比较. 另一个方法是hasAuthority(String authority)
     * hasAnyRole(String… roles) 允许多个角色访问. 另一个方法是hasAnyAuthority(String… authorities)
     * access(String attribute) 该方法使用 SPEL, 所以可以创建复杂的限制 例如如access("permitAll"), access("hasRole('ADMIN') and hasIpAddress('123.123.123.123')")
     * hasIpAddress(String ipaddressExpression) 限制IP地址或子网
     * 三 登录login
     * formLogin() 基于表单登录
     * loginPage() 登录页
     * defaultSuccessUrl 登录成功后的默认处理页
     * failuerHandler登录失败之后的处理器
     * successHandler登录成功之后的处理器
     * failuerUrl登录失败之后系统转向的url，默认是this.loginPage + "?error"
     * 四 登出logout
     * logoutUrl 登出url ， 默认是/logout， 它可以是一个ant path url
     * logoutSuccessUrl 登出成功后跳转的 url 默认是"/login?logout"
     * logoutSuccessHandler 登出成功处理器，设置后会把logoutSuccessUrl 置为null
     * 下面的代码片段就不会拦截/user,因为只会匹配"/api/**"
     * @param httpSecurity
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
                .csrf().disable()//禁用CSRF机制 CSRF机制要多一个参数
                .formLogin()//指定支持基于表单的身份验证。
                    .loginProcessingUrl("/login").permitAll()
                    .successHandler(successHandler).permitAll() //登录成功的处理
                    .failureHandler(failureHandler).permitAll().and()
                .logout().logoutSuccessHandler(logoutHandler).and() //oauth/logout
                .authorizeRequests().antMatchers("/**").permitAll(); ///**请求不需要权限认证

    }
}
