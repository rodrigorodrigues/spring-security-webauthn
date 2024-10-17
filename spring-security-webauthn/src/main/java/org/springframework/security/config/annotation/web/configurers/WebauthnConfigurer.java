/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.configurers;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.security.web.authentication.ui.DefaultWebauthnLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import org.springframework.security.web.webauthn.registration.DefaultWebAuthnRegistrationPageGeneratingFilter;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsFilter;
import org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter;
import org.springframework.security.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.webauthn.authentication.WebAuthnAuthenticationProvider;
import org.springframework.security.webauthn.management.*;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.lang.reflect.Constructor;
import java.util.*;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

/**
 * Configures WebAuthn for Spring Security applications
 * @since 6.4
 * @author Rob Winch
 * @param <B> the type of builder
 */
public class WebauthnConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<WebauthnConfigurer<B>, B> {
	private final AuthorizationEndpointConfig authorizationEndpointConfig = new AuthorizationEndpointConfig();

	private String rpId;

	private String rpName;

	private Set<String> allowedOrigins = new HashSet<>();


	public WebauthnConfigurer<B> rpId(String rpId) {
		this.rpId = rpId;
		return this;
	}

	public WebauthnConfigurer<B> rpName(String rpName) {
		this.rpName = rpName;
		return this;
	}

	public WebauthnConfigurer<B> allowedOrigins(String... allowedOrigins) {
		this.allowedOrigins = Set.of(allowedOrigins);
		return this;
	}

	@Override
	public void configure(B http) throws Exception {
		UserDetailsService userDetailsService = getSharedOrBean(http, UserDetailsService.class).get();
		PublicKeyCredentialUserEntityRepository userEntities = getSharedOrBean(http, PublicKeyCredentialUserEntityRepository.class)
				.orElse(userEntityRepository());
		UserCredentialRepository userCredentials = getSharedOrBean(http, UserCredentialRepository.class)
				.orElse(userCredentialRepository());
		WebAuthnRelyingPartyOperations rpOperations = webAuthnRelyingPartyOperations(userEntities, userCredentials);
		WebAuthnAuthenticationFilter webAuthnAuthnFilter = new WebAuthnAuthenticationFilter();
		webAuthnAuthnFilter.setAuthenticationManager(new ProviderManager(new WebAuthnAuthenticationProvider(rpOperations, userDetailsService)));
		http.addFilterBefore(webAuthnAuthnFilter, BasicAuthenticationFilter.class);
		http.addFilterAfter(new WebAuthnRegistrationFilter(userCredentials, rpOperations), AuthorizationFilter.class);
		http.addFilterBefore(new PublicKeyCredentialCreationOptionsFilter(rpOperations), AuthorizationFilter.class);
		http.addFilterAfter(new DefaultWebAuthnRegistrationPageGeneratingFilter(userEntities, userCredentials), AuthorizationFilter.class);
		http.addFilterBefore(new PublicKeyCredentialRequestOptionsFilter(rpOperations), AuthorizationFilter.class);
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null) {
			ClassPathResource webauthn = new ClassPathResource("org/springframework/security/spring-security-webauthn.js");
			AntPathRequestMatcher matcher = antMatcher(GET, "/login/webauthn.js");

			Constructor<DefaultResourcesFilter> constructor = DefaultResourcesFilter.class.getDeclaredConstructor(RequestMatcher.class, ClassPathResource.class, MediaType.class);
			constructor.setAccessible(true);
			DefaultResourcesFilter resourcesFilter =
					constructor.newInstance(matcher, webauthn, MediaType.parseMediaType("text/javascript"));
			http.addFilter(resourcesFilter);
			UsernamePasswordAuthenticationFilter usernamePasswordFilter = http.getSharedObject(UsernamePasswordAuthenticationFilter.class);
			DefaultWebauthnLoginPageGeneratingFilter webauthnLogin = new DefaultWebauthnLoginPageGeneratingFilter(usernamePasswordFilter);
			webauthnLogin.setFormLoginEnabled(true);
			webauthnLogin.setPasskeysEnabled(true);
			webauthnLogin.setOauth2LoginEnabled(true);
			webauthnLogin.setOauth2AuthenticationUrlToClientName(this.getLoginLinks());
			webauthnLogin.setResolveHeaders((request) -> {
				CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
				return Map.of( csrfToken.getHeaderName(), csrfToken.getToken());
			});
			boolean ottEnabled = isOttEnabled(http);
			if (ottEnabled) {
				webauthnLogin.setOneTimeTokenEnabled(true);
				webauthnLogin.setGenerateOneTimeTokenUrl("/ott/generate");
			}
			webauthnLogin.setLoginPageUrl("/login");
			webauthnLogin.setAuthenticationUrl("/login");
			webauthnLogin.setFailureUrl("/login?error");
			webauthnLogin.setUsernameParameter("username");
			webauthnLogin.setPasswordParameter("password");
			webauthnLogin.setResolveHiddenInputs(this::hiddenInputs);
			http.addFilterBefore(webauthnLogin, DefaultLoginPageGeneratingFilter.class);
		}
	}

	private Map<String, String> getLoginLinks() {
		Iterable<ClientRegistration> clientRegistrations = null;
		ClientRegistrationRepository clientRegistrationRepository = OAuth2ClientConfigurerUtils
				.getClientRegistrationRepository(this.getBuilder());
		ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
		if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
			clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
		}
		if (clientRegistrations == null) {
			return Collections.emptyMap();
		}
		String authorizationRequestBaseUri = (this.authorizationEndpointConfig.authorizationRequestBaseUri != null)
				? this.authorizationEndpointConfig.authorizationRequestBaseUri
				: OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
		Map<String, String> loginUrlToClientName = new HashMap<>();
		clientRegistrations.forEach((registration) -> {
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())) {
				String authorizationRequestUri = authorizationRequestBaseUri + "/" + registration.getRegistrationId();
				loginUrlToClientName.put(authorizationRequestUri, registration.getClientName());
			}
		});
		return loginUrlToClientName;
	}

	public static <B extends HttpSecurityBuilder<B>> WebauthnConfigurer<B> webauthn() {
		return new WebauthnConfigurer<>();
	}

	private boolean isOttEnabled(B http) {
		try {
			Class ottConfigurer = ClassUtils.forName("org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer", WebauthnConfigurer.class.getClassLoader());
			return http.getConfigurer(ottConfigurer) != null;
		}
		catch (Exception ex) {
			return false;
		}
	}

	private Map<String, String> hiddenInputs(HttpServletRequest request) {
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		return (token != null) ? Collections.singletonMap(token.getParameterName(), token.getToken())
				: Collections.emptyMap();
	}

	private <C> Optional<C> getSharedOrBean(B http, Class<C> type) {
		C shared = http.getSharedObject(type);
		return Optional
			.ofNullable(shared)
			.or(() -> getBeanOrNull(type));
	}

	private <T> Optional<T> getBeanOrNull(Class<T> type) {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		if (context == null) {
			return Optional.empty();
		}
		try {
			return Optional.of(context.getBean(type));
		}
		catch (NoSuchBeanDefinitionException ex) {
			return Optional.empty();
		}
	}


	private MapUserCredentialRepository userCredentialRepository() {
		return new MapUserCredentialRepository();
	}

	private PublicKeyCredentialUserEntityRepository userEntityRepository() {
		return new MapPublicKeyCredentialUserEntityRepository();
	}

	private WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository userCredentials) {
		Optional<WebAuthnRelyingPartyOperations> webauthnOperationsBean = getBeanOrNull(WebAuthnRelyingPartyOperations.class);
		if (webauthnOperationsBean.isPresent()) {
			return webauthnOperationsBean.get();
		}
		Webauthn4JRelyingPartyOperations result =  new Webauthn4JRelyingPartyOperations(userEntities, userCredentials,
				PublicKeyCredentialRpEntity.builder()
				.id(this.rpId)
				.name(this.rpName)
				.build(),
				this.allowedOrigins);
		return result;
	}

	private final class AuthorizationEndpointConfig {
		private String authorizationRequestBaseUri;
		private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
		private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
		private RedirectStrategy authorizationRedirectStrategy;

		private AuthorizationEndpointConfig() {
		}

		public WebauthnConfigurer<B>.AuthorizationEndpointConfig baseUri(String authorizationRequestBaseUri) {
			Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
			this.authorizationRequestBaseUri = authorizationRequestBaseUri;
			return this;
		}

		public WebauthnConfigurer<B>.AuthorizationEndpointConfig authorizationRequestResolver(OAuth2AuthorizationRequestResolver authorizationRequestResolver) {
			Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
			this.authorizationRequestResolver = authorizationRequestResolver;
			return this;
		}

		public WebauthnConfigurer<B>.AuthorizationEndpointConfig authorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
			Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
			this.authorizationRequestRepository = authorizationRequestRepository;
			return this;
		}

		public WebauthnConfigurer<B>.AuthorizationEndpointConfig authorizationRedirectStrategy(RedirectStrategy authorizationRedirectStrategy) {
			this.authorizationRedirectStrategy = authorizationRedirectStrategy;
			return this;
		}

		/** @deprecated */
		@Deprecated(
				since = "6.1",
				forRemoval = true
		)
		public WebauthnConfigurer<B> and() {
			return WebauthnConfigurer.this;
		}
	}
}
