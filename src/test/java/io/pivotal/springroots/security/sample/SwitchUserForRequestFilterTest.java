/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.pivotal.springroots.security.sample;

import io.pivotal.springroots.security.SwitchUserForRequestFilter;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.ArrayList;
import java.util.List;

import static io.pivotal.springroots.security.SwitchUserForRequestFilter.SWITCH_HEADER_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Shamelessly adapted from Spring Security's <code>SwitchUserFilterTests</code>.
 *
 * @author Mark St.Godard
 * @author Luke Taylor
 * @author John S. Ryan
 */
public class SwitchUserForRequestFilterTest {
	private final static List<GrantedAuthority> ROLES_12 = AuthorityUtils
		.createAuthorityList("ROLE_ONE", "ROLE_TWO");

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Before
	public void authenticateCurrentUser() {
		UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
			"dano", "hawaii50");
		SecurityContextHolder.getContext().setAuthentication(auth);
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	@Ignore("Not implemented, yet.")
	public void requiresSwitchMatchesCorrectly() {
		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setSwitchUserHeader("X-Impersonate-Me");

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("X-Impersonate-Me", "jacklord");
		request.setRequestURI("/any/path/to/a/resource");

		assertThat(filter.requiresSwitchUser(request)).isTrue();
	}

	@Test(expected = UsernameNotFoundException.class)
	@Ignore("Not implemented, yet.")
	public void attemptSwitchToUnknownUserFails() throws Exception {

		MockHttpServletRequest request = createMockSwitchRequest("user-that-doesnt-exist");

		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setUserDetailsService(new MockUserDetailsService());
		filter.attemptSwitchUser(request);
	}

	@Test
	@Ignore("Not implemented, yet.")
	public void attemptSwitchUserIsSuccessfulWithValidUser() throws Exception {
		assertThat(switchToUser("jacklord")).isNotNull();
	}

	@Test(expected = DisabledException.class)
	@Ignore("Not implemented, yet.")
	public void attemptSwitchToUserThatIsDisabledFails() throws Exception {
		switchToUser("mcgarrett");
	}

	@Test(expected = AccountExpiredException.class)
	@Ignore("Not implemented, yet.")
	public void attemptSwitchToUserWithAccountExpiredFails() throws Exception {
		switchToUser("wofat");
	}

	@Test(expected = CredentialsExpiredException.class)
	@Ignore("Not implemented, yet.")
	public void attemptSwitchToUserWithExpiredCredentialsFails() throws Exception {
		switchToUser("steve");
	}

	@Test(expected = UsernameNotFoundException.class)
	@Ignore("Not implemented, yet.")
	public void switchUserWithNullUsernameThrowsException() throws Exception {
		switchToUser(null);
	}

	@Test
	@Ignore("Not implemented, yet.")
	public void whenSwitchUserFailsFilterChainIsInterrupted() throws Exception {
		MockHttpServletRequest request = createMockSwitchRequest("mcgarrett");
		MockHttpServletResponse response = new MockHttpServletResponse();
		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setUserDetailsService(new MockUserDetailsService());
		filter.afterPropertiesSet();

		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verify(chain, never()).doFilter(request, response);

		assertThat(response.getErrorMessage()).isNotNull();
	}

	@Test(expected = IllegalArgumentException.class)
	@Ignore("Not implemented, yet.")
	public void configMissingUserDetailsServiceFails() throws Exception {
		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setSwitchUserHeader(SWITCH_HEADER_NAME);
		filter.afterPropertiesSet();
	}

	@Test
	@Ignore("Not implemented, yet.")
	public void whenSwitchSucceedsRemainderOfChainExecutesAsImpersonatedUser() throws Exception {
		// set current user
		UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
			"dano", "hawaii50");
		SecurityContextHolder.getContext().setAuthentication(auth);

		MockHttpServletRequest request = createMockSwitchRequest("jacklord");
		MockHttpServletResponse response = new MockHttpServletResponse();

		// setup filter
		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setUserDetailsService(new MockUserDetailsService());

		AuthenticationCapture captureAuthentication = new AuthenticationCapture();
		FilterChain chain = mock(FilterChain.class);
		doAnswer(captureAuthentication)
			.when(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));

		filter.doFilter(request, response, chain);
		verify(chain).doFilter(request, response);

		// verify remainder of chain was invoked as jacklord
		Authentication targetAuth = captureAuthentication.getAuthentication();
		assertThat(targetAuth).isNotNull();
		assertThat(targetAuth.getPrincipal() instanceof UserDetails).isTrue();
		assertThat(((User) targetAuth.getPrincipal()).getUsername()).isEqualTo("jacklord");
	}

	private static class AuthenticationCapture implements Answer {
		private Authentication capturedAuthentication;

		@Override
		public Object answer(InvocationOnMock invocation) throws Throwable {
			capturedAuthentication = SecurityContextHolder.getContext().getAuthentication();
			return null;
		}

		public Authentication getAuthentication() {
			return capturedAuthentication;
		}
	}

	@Test
	@Ignore("Not implemented, yet.")
	public void whenFilterCompletesOriginalUserIsRestored() throws Exception {
		// set current user
		UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
			"dano", "hawaii50");
		SecurityContextHolder.getContext().setAuthentication(auth);

		MockHttpServletRequest request = createMockSwitchRequest("jacklord");
		MockHttpServletResponse response = new MockHttpServletResponse();

		// setup filter
		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setUserDetailsService(new MockUserDetailsService());
		FilterChain chain = mock(FilterChain.class);

		// test updates user token and context
		filter.doFilter(request, response, chain);
		verify(chain).doFilter(request, response);

		// verify "dano" is back.
		Authentication targetAuth = SecurityContextHolder.getContext().getAuthentication();
		assertThat(targetAuth).isNotNull();
		assertThat(targetAuth.getPrincipal() instanceof UserDetails).isTrue();
		assertThat(((User) targetAuth.getPrincipal()).getUsername()).isEqualTo("dano");
	}

	@Test(expected = AuthenticationException.class)
	@Ignore("Not implemented, yet.")
	public void switchUserWithNoCurrentUserFails() throws Exception {
		// no current user in secure context
		SecurityContextHolder.clearContext();

		MockHttpServletRequest request = createMockSwitchRequest("targetUsername");
		request.addHeader(SWITCH_HEADER_NAME, "jacklord");
		request.setRequestURI("/path/to/some/resource");

		// setup filter
		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setUserDetailsService(new MockUserDetailsService());

		FilterChain chain = mock(FilterChain.class);
		MockHttpServletResponse response = new MockHttpServletResponse();

		try {
			filter.doFilter(request, response, chain);
		} finally {
			// "fails" also means chain was interrupted.
			verify(chain, never()).doFilter(request, response);
		}
	}

	@Test
	@Ignore("Not implemented, yet.")
	public void modificationOfAuthoritiesWorks() {
		UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
			"dano", "hawaii50");
		SecurityContextHolder.getContext().setAuthentication(auth);

		MockHttpServletRequest request = createMockSwitchRequest("jacklord");

		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setUserDetailsService(new MockUserDetailsService());
		filter.setSwitchUserAuthorityChanger(
			(targetUser, currentAuthentication, authoritiesToBeGranted) -> {
				List<GrantedAuthority> auths = new ArrayList<GrantedAuthority>();
				auths.add(new SimpleGrantedAuthority("ROLE_NEW"));
				return auths;
			});

		Authentication result = filter.attemptSwitchUser(request);
		assertThat(result).isNotNull();
		assertThat(result.getAuthorities()).hasSize(2);
		assertThat(AuthorityUtils.authorityListToSet(result.getAuthorities())).contains(
			"ROLE_NEW");
	}

	// SEC-1763
	@Test
	@Ignore("Not implemented, yet.")
	public void nestedSwitchesAreNotAllowed() throws Exception {
		// authentication is already switched (e.g. through the SwitchUserFilter)
		UsernamePasswordAuthenticationToken source = new UsernamePasswordAuthenticationToken(
			"orig", "hawaii50", ROLES_12);
		SecurityContextHolder.getContext().setAuthentication(source);
		SecurityContextHolder.getContext().setAuthentication(switchToUser("jacklord"));

		// attempt to switch again
		Authentication switched = switchToUser("dano");

		SwitchUserGrantedAuthority switchedFrom = (SwitchUserGrantedAuthority)
			switched.getAuthorities().stream()
				.filter((ga) -> ga instanceof SwitchUserGrantedAuthority)
				.findFirst()
				.orElse(null);

		// switch back will continue to be the original source.
		assertThat(switchedFrom).isNotNull();
		assertThat(source).isSameAs(switchedFrom.getSource());
	}

	// gh-3697
	@Test
	@Ignore("Not implemented, yet.")
	public void switchAuthorityRoleCannotBeNull() throws Exception {
		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("switchAuthorityRole cannot be null");
		MockHttpServletRequest request = createMockSwitchRequest("dano");

		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setUserDetailsService(new MockUserDetailsService());
		filter.setSwitchAuthorityRole(null);

		filter.attemptSwitchUser(request);
	}

	// gh-3697
	@Test
	@Ignore("Not implemented, yet.")
	public void switchAuthorityRoleCanBeChanged() throws Exception {
		String switchAuthorityRole = "PREVIOUS_ADMINISTRATOR";

		// original user
		UsernamePasswordAuthenticationToken source = new UsernamePasswordAuthenticationToken(
			"orig", "hawaii50", ROLES_12);
		SecurityContextHolder.getContext().setAuthentication(source);
		SecurityContextHolder.getContext().setAuthentication(switchToUser("jacklord"));
		MockHttpServletRequest request = createMockSwitchRequest("dano");

		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setUserDetailsService(new MockUserDetailsService());
		filter.setSwitchAuthorityRole(switchAuthorityRole);

		Authentication switched = filter.attemptSwitchUser(request);

		SwitchUserGrantedAuthority switchedFrom = (SwitchUserGrantedAuthority)
			switched.getAuthorities().stream()
				.filter((ga) -> ga instanceof SwitchUserGrantedAuthority)
				.findFirst()
				.orElse(null);

		assertThat(switchedFrom).isNotNull();
		assertThat(switchedFrom.getSource()).isSameAs(source);
		assertThat(switchAuthorityRole).isEqualTo(switchedFrom.getAuthority());
	}

	private MockHttpServletRequest createMockSwitchRequest(String targetUsername) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setScheme("http");
		request.setServerName("localhost");
		request.addHeader(SWITCH_HEADER_NAME, targetUsername);
		request.setRequestURI("/path/to/some/resource");
		return request;
	}

	private Authentication switchToUser(String targetUsername) {
		MockHttpServletRequest request = createMockSwitchRequest(targetUsername);
		SwitchUserForRequestFilter filter = new SwitchUserForRequestFilter();
		filter.setUserDetailsService(new MockUserDetailsService());
		return filter.attemptSwitchUser(request);
	}

	// ~ Inner Classes
	// ==================================================================================================

	private class MockUserDetailsService implements UserDetailsService {
		private String password = "hawaii50";

		public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
			// jacklord, dano (active)
			// mcgarrett (disabled)
			// wofat (account expired)
			// steve (credentials expired)
			if ("jacklord".equals(username) || "dano".equals(username)) {
				return new User(username, password, true, true, true, true, ROLES_12);
			} else if ("mcgarrett".equals(username)) {
				return new User(username, password, false, true, true, true, ROLES_12);
			} else if ("wofat".equals(username)) {
				return new User(username, password, true, false, true, true, ROLES_12);
			} else if ("steve".equals(username)) {
				return new User(username, password, true, true, false, true, ROLES_12);
			} else {
				throw new UsernameNotFoundException("Could not find: " + username);
			}
		}
	}
}
