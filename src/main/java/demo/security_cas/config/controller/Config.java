package demo.security_cas.config.controller;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;

import vn.com.vndirect.basicservice.vndssecuritycas.config.DefaultSecurityConfiguration;

@Configuration
@EnableWebSecurity
public class Config extends DefaultSecurityConfiguration {

}
