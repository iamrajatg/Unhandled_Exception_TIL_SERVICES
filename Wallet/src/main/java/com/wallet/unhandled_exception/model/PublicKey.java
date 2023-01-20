package com.wallet.unhandled_exception.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class PublicKey implements Serializable {
	
	@JsonProperty("id")
	private String id;
	
	@JsonProperty("type")
	private String type;
	
	@JsonProperty("controller")
	private String controller;
	
	@JsonProperty("publicKeyBase58")
	private String publicKeyBase58;

	public PublicKey() {
		super();
	}

	@Override
	public String toString() {
		return "PublicKey [id=" + id + ", type=" + type + ", controller=" + controller + ", publicKeyBase58="
				+ publicKeyBase58 + "]";
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getController() {
		return controller;
	}

	public void setController(String controller) {
		this.controller = controller;
	}

	public String getPublicKeyBase58() {
		return publicKeyBase58;
	}

	public void setPublicKeyBase58(String publicKeyBase58) {
		this.publicKeyBase58 = publicKeyBase58;
	}
}
