package com.testcxtx.uaa;


import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class TestBCrypt {


    @Test
    public void test(){
        String ps = BCrypt.hashpw("secret",BCrypt.gensalt());
        System.out.println(ps);
        boolean check = BCrypt.checkpw("123","$2a$10$cA012zaZzM9S1oZJpzA5kuGGFOCt9aKxlCxAld1.Txe1LoyvXIEh.");
        System.out.println(check);
    }
}
