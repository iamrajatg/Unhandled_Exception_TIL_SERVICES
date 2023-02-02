package com.wallet.unhandled_exception.response;

import java.io.Serializable;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.wallet.unhandled_exception.model.DID_Doc;


@JsonInclude(JsonInclude.Include.NON_NULL)
public class FinalResponse implements Serializable{
	

	@JsonProperty("did_key")
	private String did_key;
	
	@JsonProperty("publicKey")
	private String publicKey;
	
	@JsonProperty("privateKey")
	private String privateKey;
	

	@JsonProperty("did_web")
	private String did_web;
	
	@JsonProperty("did_document")
	private DID_Doc did_document;

	@Override
	public String toString() {
		return "FinalResponse [did_key=" + did_key + ", did_web=" + did_web + ", did_document=" + did_document + "]";
	}

	public FinalResponse() {
		super();
	}	
	
	public FinalResponse(String did_key, String did_web, DID_Doc did_document, String publicKey , String privateKey) {
		super();
		this.did_key = did_key;
		this.did_web = did_web;
		this.did_document = did_document;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public String getDid_key() {
		return did_key;
	}

	public void setDid_key(String did_key) {
		this.did_key = did_key;
	}

	public String getDid_web() {
		return did_web;
	}
	
	public String setPublicKey(String publicKey) {
		return this.publicKey =  publicKey;
	}
	
	public String setPrivateKey(String privateKey) {
		return this.privateKey =  privateKey;
	}

	public void setDid_web(String did_web) {
		this.did_web = did_web;
	}

	public DID_Doc getDid_document() {
		return did_document;
	}

	public void setDid_document(DID_Doc did_Doc) {
		this.did_document = did_Doc;
	}
}
