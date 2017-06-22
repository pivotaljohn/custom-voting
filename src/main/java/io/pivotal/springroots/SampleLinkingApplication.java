package io.pivotal.springroots;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
public class SampleLinkingApplication {

	public static void main(String[] args) {
		SpringApplication.run(SampleLinkingApplication.class, args);
	}
}
