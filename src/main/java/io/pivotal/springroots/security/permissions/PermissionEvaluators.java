package io.pivotal.springroots.security.permissions;

import io.pivotal.springroots.accounts.AccountPermission;
import io.pivotal.springroots.accounts.AccountPermissionEvaluator;
import io.pivotal.springroots.providers.Provider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Slf4j
@Component
public class PermissionEvaluators implements PermissionEvaluator {

	private final AccountPermissionEvaluator accountPermissionEvaluator;

	public PermissionEvaluators(AccountPermissionEvaluator accountPermissionEvaluator) {
		this.accountPermissionEvaluator = accountPermissionEvaluator;
	}

	@Override
	public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
		return false;
	}

	@Override
	public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
		boolean permitted = false;
		if(permission instanceof AccountPermission) {
			Provider provider = (Provider) authentication.getDetails();
			permitted = accountPermissionEvaluator.hasPermission(provider, (String) targetId, (AccountPermission) permission);
		}

		return permitted;
	}
}
