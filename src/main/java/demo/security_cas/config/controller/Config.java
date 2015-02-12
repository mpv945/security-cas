package demo.security_cas.config.controller;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import vn.com.vndirect.basicservice.vndssecuritycas.config.DefaultSecurityConfiguration;

@Configuration
@EnableWebSecurity
public class Config extends DefaultSecurityConfiguration {
	
	@Override
	public void todoConfigure(HttpSecurity http) throws Exception {
		super.todoConfigure(http);
		
	}
}
