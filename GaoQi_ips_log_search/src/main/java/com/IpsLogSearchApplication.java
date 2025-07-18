package com;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.elasticsearch.ElasticsearchDataAutoConfiguration;
import org.springframework.data.elasticsearch.repository.config.EnableElasticsearchRepositories;

@SpringBootApplication(exclude = {ElasticsearchDataAutoConfiguration.class})
@EnableElasticsearchRepositories(basePackages = "com.repository")
public class IpsLogSearchApplication {

    public static void main(String[] args) {
        SpringApplication.run(IpsLogSearchApplication.class, args);
    }
}