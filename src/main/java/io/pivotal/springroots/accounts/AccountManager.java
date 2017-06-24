package io.pivotal.springroots.accounts;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class AccountManager {

	@PreAuthorize(
		"hasRole('PROGRAM_HUB') or " +
		"(hasRole('RETAILER') and @securityChecks.canLink(principal, #sourceAccountId))"
	)
	public void linkAccount(String sourceAccountId, String targetAccountId) {
		log.trace("linkAccount(sourceAccountId = \"{}\", targetAccountId = \"{}\")", sourceAccountId, targetAccountId);

		log.trace("linkAccount() succeeded.");
	}
}
