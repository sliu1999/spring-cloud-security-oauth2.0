package com.cxtx.security_order.rest;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Sentinel限流
 * @author sliu
 * @date 2021/3/29
 */
@RestController
@RequestMapping("/api")
public class XianLiuResource {


    @GetMapping(value = "/helloP1")
    @PreAuthorize("hasAnyAuthority('p1')") //拥有配p1权限才可以访问  header 携带Authorization= Bearer + token
    public String apiHello() {
        String principal = String.valueOf(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        return principal;
    }

    @GetMapping(value = "/helloP2")
    @PreAuthorize("hasAnyAuthority('p2')") //拥有配p2权限才可以访问  header 携带Authorization= Bearer + token
    public String apiHellop() {
        SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return "hello";
    }


}