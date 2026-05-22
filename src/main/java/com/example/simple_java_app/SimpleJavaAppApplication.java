package com.example.simple_java_app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class SimpleJavaAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(SimpleJavaAppApplication.class, args);
    }

    @GetMapping("/")
    public String home() {
        return "Welcome to simple-java-app! API is running.";
    }

    @GetMapping("/health")
    public HealthResponse health() {
        return new HealthResponse("UP", "Application is healthy");
    }

    @GetMapping("/api/info")
    public InfoResponse info() {
        return new InfoResponse(
            "simple-java-app",
            "1.0.0",
            System.getenv("ENVIRONMENT") != null ? System.getenv("ENVIRONMENT") : "dev"
        );
    }

    static class HealthResponse {
        public String status;
        public String message;

        public HealthResponse(String status, String message) {
            this.status = status;
            this.message = message;
        }
    }

    static class InfoResponse {
        public String app;
        public String version;
        public String environment;

        public InfoResponse(String app, String version, String environment) {
            this.app = app;
            this.version = version;
            this.environment = environment;
        }
    }
}
