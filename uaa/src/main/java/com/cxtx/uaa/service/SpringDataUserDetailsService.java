package com.cxtx.uaa.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class SpringDataUserDetailsService implements UserDetailsService {

    //根据账号查用户信息
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails userDetails = null;
        if("zhangsan".equals(username)){
            userDetails = User.withUsername("zhangsan").password("$2a$10$cA012zaZzM9S1oZJpzA5kuGGFOCt9aKxlCxAld1.Txe1LoyvXIEh.").authorities("p1","p2").build();
        }else if("lisi".equals(username)){
            userDetails = User.withUsername("lisi").password("$2a$10$cA012zaZzM9S1oZJpzA5kuGGFOCt9aKxlCxAld1.Txe1LoyvXIEh.").authorities("p2").build();
        }
        //从数据库获取用户信息，如果不存在就返回null,有provider抛异常
                return userDetails;
    }
}
