package io.pivotal.springroots.api;

import io.pivotal.springroots.accounts.AccountManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class LinkingController {

	private final AccountManager accountManager;

	public LinkingController(AccountManager accountManager) {
		this.accountManager = accountManager;
	}

	@PostMapping("/api/link/{sourceAccountId}")
	public void linkAccount(@PathVariable String sourceAccountId,
									@RequestBody LinkRequestBody linkRequestBody) {
		log.info("linkAccount(sourceAccountId = \"" + sourceAccountId + "\")");

		accountManager.linkAccount(sourceAccountId, linkRequestBody.getTargetAccountId());

		log.info("linkAccount() succeeds.");
	}
}
