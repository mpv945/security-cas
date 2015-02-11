package demo.security_cas.config.controller;

import java.util.HashSet;
import java.util.Set;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.Saml11TicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;

import vn.com.vndirect.basicservice.vndssecuritycas.service.CustomUserDetailsService;

public class DefaultSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Bean
	public ServiceProperties serviceProperties() {
		return new DefaultServiceProperties();
	}
		
	@Bean
	public CasAuthenticationProvider casAuthenticationProvider() {
		CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
		casAuthenticationProvider.setAuthenticationUserDetailsService(customUserDetailsService());
		casAuthenticationProvider.setServiceProperties(serviceProperties());
		casAuthenticationProvider.setTicketValidator(cas20ServiceTicketValidator());
		casAuthenticationProvider.setKey("an_id_for_this_auth_provider_only");
		return casAuthenticationProvider;
	}

	@Bean
	public AuthenticationUserDetailsService<CasAssertionAuthenticationToken> customUserDetailsService() {
		return new CustomUserDetailsService(adminList());
	}
	
	@Bean
	public Set<String> adminList() {
		Set<String> admins = new HashSet<String>();
		admins.add("admin");
		return admins;
	}

	@Bean
	public SessionAuthenticationStrategy sessionStrategy() {
		SessionAuthenticationStrategy sessionStrategy = new SessionFixationProtectionStrategy();
		return sessionStrategy;
	}

	@Bean
	public Saml11TicketValidator casSamlServiceTicketValidator() {
		return new Saml11TicketValidator("https://suat.vndirect.com.vn/login/");
	}

	@Bean
	public Cas20ServiceTicketValidator cas20ServiceTicketValidator() {
		return new Cas20ServiceTicketValidator("https://suat.vndirect.com.vn/login/");
	}

	@Bean
	public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
		CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
		casAuthenticationFilter.setAuthenticationManager(authenticationManager());
		casAuthenticationFilter.setSessionAuthenticationStrategy(sessionStrategy());
		return casAuthenticationFilter;
	}

	@Bean
	public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
		CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
		casAuthenticationEntryPoint.setLoginUrl("https://suat.vndirect.com.vn/login/login");
		casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
		return casAuthenticationEntryPoint;
	}

	@Bean
	public SingleSignOutFilter singleSignOutFilter() {
		SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
		singleSignOutFilter.setCasServerUrlPrefix("https://suat.vndirect.com.vn/login/");
		return singleSignOutFilter;
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(casAuthenticationProvider());
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/fonts/**").antMatchers("/images/**").antMatchers("/scripts/**")
				.antMatchers("/styles/**").antMatchers("/views/**").antMatchers("/i18n/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.exceptionHandling()
				.authenticationEntryPoint(casAuthenticationEntryPoint()).and().addFilter(casAuthenticationFilter())
				.addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class);

		http.headers().frameOptions().disable().authorizeRequests().antMatchers("/").permitAll()
				.antMatchers("/secure").authenticated().antMatchers("/filtered")
				.hasAuthority("ROLE_ADMIN").anyRequest().authenticated();

		http.logout().logoutUrl("/logout").logoutSuccessUrl("/").invalidateHttpSession(true)
				.deleteCookies("JSESSIONID");

	}
}
