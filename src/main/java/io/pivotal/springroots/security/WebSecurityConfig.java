package io.pivotal.springroots.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.csrf().disable()
		    .httpBasic();
		// @formatter:on
	}

	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("DMA").password("dma-token").roles("PROGRAM_HUB").build());
		manager.createUser(User.withUsername("AMZ").password("amz-token").roles("RETAILER").authorities("IMPERSONATE_DMA").build());
		manager.createUser(User.withUsername("VUD").password("vud-token").roles("RETAILER").build());
		return manager;
	}
}
