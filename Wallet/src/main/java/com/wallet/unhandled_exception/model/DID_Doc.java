package com.wallet.unhandled_exception.model;

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DID_Doc implements Serializable {	

	@JsonProperty("@context")
	private List<?> context;
	
	@JsonProperty("id")
	private String id;
	
	@JsonProperty("verificationMethod")
	private List<PublicKey> publickey ;
	
	@JsonProperty("authentication")
	private List<?> authentication;
	
	@JsonProperty("assertionMethod")
	private List<?> assertionMethod;
	
	@JsonProperty("capabilityDelegation")
	private List<?> capabilityDelegation;
	
	@JsonProperty("capabilityInvocation")
	private List<?> capabilityInvocation;
	
	@JsonProperty("keyAgreement")
	private List<KeyAgreement> keyAgreement;

	public DID_Doc() {
		super();
	}

	@Override
	public String toString() {
		return "AuthorV2 [context=" + context + ", id=" + id + ", authentication=" + authentication
				+ ", assertionMethod=" + assertionMethod + ", capabilityDelegation=" + capabilityDelegation
				+ ", capabilityInvocation=" + capabilityInvocation + "]";
	}

	public List<?> getContext() {
		return context;
	}

	public void setContext(List<?> context) {
		this.context = context;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public List<PublicKey> getPublickey() {
		return publickey;
	}

	public void setPublickey(List<PublicKey> publickey) {
		this.publickey = publickey;
	}

	public List<?> getAuthentication() {
		return authentication;
	}

	public void setAuthentication(List<?> authentication) {
		this.authentication = authentication;
	}

	public List<?> getAssertionMethod() {
		return assertionMethod;
	}

	public void setAssertionMethod(List<?> assertionMethod) {
		this.assertionMethod = assertionMethod;
	}

	public List<?> getCapabilityDelegation() {
		return capabilityDelegation;
	}

	public void setCapabilityDelegation(List<?> capabilityDelegation) {
		this.capabilityDelegation = capabilityDelegation;
	}

	public List<?> getCapabilityInvocation() {
		return capabilityInvocation;
	}

	public void setCapabilityInvocation(List<?> capabilityInvocation) {
		this.capabilityInvocation = capabilityInvocation;
	}

	public List<KeyAgreement> getKeyAgreement() {
		return keyAgreement;
	}

	public void setKeyAgreement(List<KeyAgreement> keyAgreement) {
		this.keyAgreement = keyAgreement;
	}		
}
