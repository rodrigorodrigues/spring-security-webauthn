package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.core.BufferSource;

import java.util.*;

public class MapUserCredentialRepository implements UserCredentialRepository {

	private final Map<ArrayBuffer,UserCredential> credentialIdToUserCredential = new HashMap<>();

	private final Map<BufferSource,List<UserCredential>> userEntityIdToUserCredentials = new HashMap<>();


	@Override
	public void delete(ArrayBuffer credentialId) {
		UserCredential userCredential = this.credentialIdToUserCredential.remove(credentialId);
		this.userEntityIdToUserCredentials.get(userCredential).remove(userCredential);
	}

	@Override
	public void save(UserCredential userCredential) {
		this.credentialIdToUserCredential.put(userCredential.getCredentialId(), userCredential);
		this.userEntityIdToUserCredentials.computeIfAbsent(userCredential.getUserEntityUserId(), (id) -> new ArrayList<>()).add(userCredential);
	}

	@Override
	public UserCredential findByCredentialId(ArrayBuffer credentialId) {
		return this.credentialIdToUserCredential.get(credentialId);
	}

	@Override
	public List<UserCredential> findByUserId(BufferSource userId) {
		return Collections.unmodifiableList(this.userEntityIdToUserCredentials.get(userId));
	}
}
