package io.pivotal.springroots.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.switchuser.SwitchUserAuthorityChanger;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class SwitchUserForRequestFilter extends GenericFilterBean {
	public static final String SWITCH_HEADER_NAME = "X-Impersonate";

	private String switchUserHeader;
	private UserDetailsService userDetailsService;
	private SwitchUserAuthorityChanger switchUserAuthorityChanger;
	private String switchAuthorityRole;

	public void setSwitchUserHeader(String switchUserHeader) {
		this.switchUserHeader = switchUserHeader;
	}

	public String getSwitchUserHeader() {
		return switchUserHeader;
	}

	public boolean requiresSwitchUser(HttpServletRequest request) {
		return false;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	public Authentication attemptSwitchUser(HttpServletRequest request) {
		return null;
	}

	public void afterPropertiesSet() {

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

	}

	public void setSwitchUserAuthorityChanger(SwitchUserAuthorityChanger switchUserAuthorityChanger) {
		this.switchUserAuthorityChanger = switchUserAuthorityChanger;
	}

	public SwitchUserAuthorityChanger getSwitchUserAuthorityChanger() {
		return switchUserAuthorityChanger;
	}

	public void setSwitchAuthorityRole(String switchAuthorityRole) {
		this.switchAuthorityRole = switchAuthorityRole;
	}

	public String getSwitchAuthorityRole() {
		return switchAuthorityRole;
	}
}
