package io.pivotal.springroots.accounts;

import io.pivotal.springroots.providers.Provider;
import org.springframework.stereotype.Component;

@Component
public class AccountPermissionEvaluator {
	public boolean hasPermission(Provider provider, String accountId, AccountPermission permission) {
		return false;
	}
}
