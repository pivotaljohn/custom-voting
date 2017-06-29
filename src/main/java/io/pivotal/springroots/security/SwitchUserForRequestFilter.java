package io.pivotal.springroots.security;

import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.switchuser.SwitchUserAuthorityChanger;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.security.web.authentication.switchuser.SwitchUserFilter.ROLE_PREVIOUS_ADMINISTRATOR;

public class SwitchUserForRequestFilter extends GenericFilterBean {
	public static final String SWITCH_HEADER_NAME = "X-Impersonate";
	public static final String ROLE_PREVIOUS_USER = ROLE_PREVIOUS_ADMINISTRATOR;

	private String switchUserHeader = SWITCH_HEADER_NAME;
	private UserDetailsService userDetailsService;
	private SwitchUserAuthorityChanger switchUserAuthorityChanger;
	private String switchAuthorityRole = ROLE_PREVIOUS_USER;
	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

	public void setSwitchUserHeader(String switchUserHeader) {
		this.switchUserHeader = switchUserHeader;
	}

	public String getSwitchUserHeader() {
		return switchUserHeader;
	}

	public boolean requiresSwitchUser(HttpServletRequest request) {
		String switchUserValue = request.getHeader(switchUserHeader);

		return switchUserValue != null && !switchUserValue.isEmpty();
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	public Authentication attemptSwitchUser(HttpServletRequest request) {
		String targetUsername = request.getHeader(switchUserHeader);
		UserDetails targetUser = userDetailsService.loadUserByUsername(targetUsername);

		userDetailsChecker.check(targetUser);

		UsernamePasswordAuthenticationToken targetUserRequest;
		Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

		targetUserRequest = new UsernamePasswordAuthenticationToken(
			targetUser,
			targetUser.getPassword(),
			targetUser.getAuthorities()
		);

		return targetUserRequest;
	}

	public void afterPropertiesSet() {

	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (requiresSwitchUser(request)) {
			try {
				Authentication switchedAuth = attemptSwitchUser(request);
				SecurityContextHolder.getContext().setAuthentication(switchedAuth);
				chain.doFilter(req, res);
			} catch (Exception e) {
				logger.error("Authentication failed.", e);
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed: " + e.getMessage());
			}
		}
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
