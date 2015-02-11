package demo.security_cas.config.controller;

import org.jasig.cas.client.validation.TicketValidationException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
	
	@RequestMapping(value = "/secure")
	public @ResponseBody String get() throws TicketValidationException {

		return "HELLO";
	}
	
	@RequestMapping(value = "/anonymous")
	public @ResponseBody String anonymous() throws TicketValidationException {

		return "anonymous page";
	}
}
