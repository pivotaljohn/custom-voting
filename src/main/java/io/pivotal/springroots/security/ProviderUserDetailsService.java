package io.pivotal.springroots.security;

import io.pivotal.springroots.providers.Provider;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class ProviderUserDetailsService {
	private Map<String, Provider> providers;

	public ProviderUserDetailsService() {
		providers = new HashMap<>();
		providers.put("DMA", new Provider("DMA"));
		providers.put("DMA", new Provider("DMA"));
	}
}
