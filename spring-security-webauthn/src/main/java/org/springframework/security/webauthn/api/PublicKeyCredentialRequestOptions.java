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

package org.springframework.security.webauthn.api;

import org.springframework.util.Assert;

import java.io.Serializable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

/**
 * <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions">PublicKeyCredentialRequestOptions</a>
 * contains the information to create an assertion used for authentication.
 * @since 6.4
 * @author Rob Winch
 */
public class PublicKeyCredentialRequestOptions implements Serializable {
	private final Bytes challenge;

	// FIXME: a null timeout is being rendered. Should we forbid null or should we not render null.
	private final Duration timeout;

	private final String rpId;

	private final List<PublicKeyCredentialDescriptor> allowCredentials;

	// FIXME: a null userVerification is being rendered, should we forbid null or should we not render null. I think that preferred is the default
	private final UserVerificationRequirement userVerification;

	// FIXME: Add hints https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-hints

	// FIXME: Add attestation https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-attestation

	// FIXME: Add attestationFormats https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-attestationformats

	private final AuthenticationExtensionsClientInputs extensions;

	private PublicKeyCredentialRequestOptions(Bytes challenge, Duration timeout, String rpId, List<PublicKeyCredentialDescriptor> allowCredentials, UserVerificationRequirement userVerification, AuthenticationExtensionsClientInputs extensions) {
		this.challenge = challenge;
		this.timeout = timeout;
		this.rpId = rpId;
		this.allowCredentials = allowCredentials;
		this.userVerification = userVerification;
		this.extensions = extensions;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-challenge">challenge</a>
	 * property specifies a challenge that the authenticator signs, along with other data, when producing an
	 * authentication assertion.
	 * @return the challenge
	 */
	public Bytes getChallenge() {
		return this.challenge;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-timeout">timeout</a>
	 * property is an OPTIONAL member specifies a time, in milliseconds, that the Relying Party is willing to wait for
	 * the call to complete.
	 * @return the timeout
	 */
	public Duration getTimeout() {
		return this.timeout;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-rpid">rpId</a> is an
	 *  OPTIONAL member specifies the RP ID claimed by the Relying Party. The client MUST verify that the Relying
	 *  Party's origin matches the scope of this RP ID.
	 * @return the relying party id
	 */
	public String getRpId() {
		return this.rpId;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a>
	 * property is an OPTIONAL member is used by the client to find authenticators eligible for this authentication
	 * ceremony.
	 * @return the allowCredentials property
	 */
	public List<PublicKeyCredentialDescriptor> getAllowCredentials() {
		return this.allowCredentials;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-userverification">userVerification</a>
	 * property is an OPTIONAL member specifies the Relying Party's requirements regarding user verification for the
	 * get() operation.
	 * @return the user verification
	 */
	public UserVerificationRequirement getUserVerification() {
		return this.userVerification;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-extensions">extensions</a>
	 * is an OPTIONAL property used by the Relying Party to provide client extension inputs requesting additional
	 * processing by the client and authenticator.
	 * @return the extensions
	 */
	public AuthenticationExtensionsClientInputs getExtensions() {
		return this.extensions;
	}

	/**
	 * Creates a {@link PublicKeyCredentialRequestOptionsBuilder}
	 * @return the {@link PublicKeyCredentialRequestOptionsBuilder}
	 */
	public static PublicKeyCredentialRequestOptionsBuilder builder() {
		return new PublicKeyCredentialRequestOptionsBuilder();
	}

	/**
	 * Used to build a {@link PublicKeyCredentialCreationOptions}.
	 * @since 6.4
	 * @author Rob Winch
	 */
	public static final class PublicKeyCredentialRequestOptionsBuilder {
		private Bytes challenge;
		private Duration timeout;
		private String rpId;
		private List<PublicKeyCredentialDescriptor> allowCredentials = Collections.emptyList();
		private UserVerificationRequirement userVerification;
		private AuthenticationExtensionsClientInputs extensions = new ImmutableAuthenticationExtensionsClientInputs(new ArrayList<>());

		private PublicKeyCredentialRequestOptionsBuilder() {
		}

		/**
		 * Sets the {@link #getChallenge()} property.
		 * @param challenge the challenge
		 * @return the {@link PublicKeyCredentialRequestOptionsBuilder}
		 */
		public PublicKeyCredentialRequestOptionsBuilder challenge(Bytes challenge) {
			this.challenge = challenge;
			return this;
		}

		/**
		 * Sets the {@link #getTimeout()} property.
		 * @param timeout the timeout
		 * @return the {@link PublicKeyCredentialRequestOptionsBuilder}
		 */
		public PublicKeyCredentialRequestOptionsBuilder timeout(Duration timeout) {
			this.timeout = timeout;
			return this;
		}

		/**
		 * Sets the {@link #getRpId()} property.
		 * @param rpId the rpId property
		 * @return the {@link PublicKeyCredentialRequestOptionsBuilder}
		 */
		public PublicKeyCredentialRequestOptionsBuilder rpId(String rpId) {
			this.rpId = rpId;
			return this;
		}

		/**
		 * Sets the {@link #getAllowCredentials()} property
		 * @param allowCredentials the allowed credentials
		 * @return the {@link PublicKeyCredentialRequestOptionsBuilder}
		 */
		public PublicKeyCredentialRequestOptionsBuilder allowCredentials(List<PublicKeyCredentialDescriptor> allowCredentials) {
			Assert.notNull(allowCredentials, "allowCredentials cannot be null");
			this.allowCredentials = allowCredentials;
			return this;
		}

		/**
		 * Sets the {@link #getUserVerification()} property.
		 * @param userVerification the user verification
		 * @return the {@link PublicKeyCredentialRequestOptionsBuilder}
		 */
		public PublicKeyCredentialRequestOptionsBuilder userVerification(UserVerificationRequirement userVerification) {
			this.userVerification = userVerification;
			return this;
		}

		/**
		 * Sets the {@link #getExtensions()} property
		 * @param extensions the extensions
		 * @return the {@link PublicKeyCredentialRequestOptionsBuilder}
		 */
		public PublicKeyCredentialRequestOptionsBuilder extensions(AuthenticationExtensionsClientInputs extensions) {
			this.extensions = extensions;
			return this;
		}

		/**
		 * Allows customizing the {@link PublicKeyCredentialRequestOptionsBuilder}
		 * @param customizer the {@link Consumer} used to customize the builder
		 * @return the {@link PublicKeyCredentialRequestOptionsBuilder}
		 */
		public PublicKeyCredentialRequestOptionsBuilder customize(Consumer<PublicKeyCredentialRequestOptionsBuilder> customizer) {
			customizer.accept(this);
			return this;
		}

		/**
		 * Builds a new {@link PublicKeyCredentialRequestOptions}
		 * @return a new {@link PublicKeyCredentialRequestOptions}
		 */
		public PublicKeyCredentialRequestOptions build() {
			return new PublicKeyCredentialRequestOptions(this.challenge, this.timeout, this.rpId,
					this.allowCredentials, this.userVerification, this.extensions);
		}

	}

}
