package com.compsec.ps3pwned;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class PS3PwnedApplication {

    public static void main(String[] args) {
        SpringApplication.run(PS3PwnedApplication.class, args);
    }

}
