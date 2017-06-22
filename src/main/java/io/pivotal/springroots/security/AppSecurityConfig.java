package io.pivotal.springroots.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
public class AppSecurityConfig extends GlobalMethodSecurityConfiguration {

	private final PermissionEvaluator permissionEvalutators;

	@Autowired
	public AppSecurityConfig(PermissionEvaluator permissionEvalutators) {
		this.permissionEvalutators = permissionEvalutators;
	}

	@Override
	protected MethodSecurityExpressionHandler createExpressionHandler() {
		DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
		handler.setPermissionEvaluator(permissionEvalutators);
		return handler;
	}
}
