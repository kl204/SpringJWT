package com.example.springjwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {


    @Override
    public void addCorsMappings(CorsRegistry corsRegistry){

        // 모든 Controller 경로에 대해서 3000번대에서 오는 요청을 허용한다.
        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:3000");
    }


}
