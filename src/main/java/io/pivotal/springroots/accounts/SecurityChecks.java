package io.pivotal.springroots.accounts;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.*;

@Slf4j
@Component
public class SecurityChecks {
	private List<String> retailersThatCanLink;
	private Map<String, Set<String>> testAccountsForRetailer;

	public SecurityChecks() {
		retailersThatCanLink = new ArrayList<>();
		retailersThatCanLink.add("APL");

		testAccountsForRetailer = new HashMap<>();
		Set<String> accountIds = new HashSet<>();
		accountIds.add("test-0001");
		accountIds.add("swid");
		testAccountsForRetailer.put("AMZ", accountIds);
	}

	public boolean canImpersonateLink(UserDetails principal, String accountId) {
		log.trace("provider = {}; accountId = {}", principal, accountId);
		boolean hasPermission;

		Set<String> accountIds = testAccountsForRetailer.get(principal.getUsername());
		log.trace("accountIds for provider = {}", accountIds);
		if (accountIds == null) {
			log.warn("No permissions found for provider.");
			return false;
		}
		hasPermission = accountIds.contains(accountId);
		log.trace("hasPermission = {}", hasPermission);
		return hasPermission;
	}
}
