package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.core.BufferSource;

public interface UserCredential {

	ArrayBuffer getCredentialId();

	BufferSource getUserEntityUserId();

	PublicKeyCose getPublicKeyCose();

	long getSignatureCount();

	OptionalBoolean getBackupEligible();

	OptionalBoolean getBackupState();
}
