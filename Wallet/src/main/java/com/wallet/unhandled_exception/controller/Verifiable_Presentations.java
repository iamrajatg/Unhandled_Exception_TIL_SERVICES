package com.wallet.unhandled_exception.controller;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.VerifiablePresentation;
import com.danubetech.verifiablecredentials.jsonld.VerifiableCredentialContexts;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2018LdSigner;

@RestController
@RequestMapping("/wallet/presentations/")
public class Verifiable_Presentations {
	@GetMapping("/sign")
	public String signin() throws DecoderException
	{
		Map<String, Object> claims = new LinkedHashMap<>();
		Map<String, Object> degree = new LinkedHashMap<>();
		degree.put("name", "Rupal_Goyal");
		degree.put("type", "Prime_Subscriber");
		claims.put("company", "Times_of_India");
		claims.put("Exclusive", degree);

		CredentialSubject credentialSubject = CredentialSubject.builder()
		        .id(URI.create("did:toi:ebfeb1f712ebc6f1c276e12ec21"))
		        .claims(claims)
		        .build();

		VerifiableCredential verifiableCredential = VerifiableCredential.builder()
		        .context(VerifiableCredentialContexts.JSONLD_CONTEXT_W3C_2018_CREDENTIALS_EXAMPLES_V1)
		        .type("TOIPlusSubscription")
		        .id(URI.create("http://toi.com/credentials/3732"))
		        .issuer(URI.create("did:toi:76e12ec712ebc6f1c221ebfeb1f"))
		        .issuanceDate(JsonLDUtils.stringToDate("2023-01-13T18:56:59Z"))
		        .expirationDate(JsonLDUtils.stringToDate("2023-03-04T18:56:59Z"))
		        .credentialSubject(credentialSubject)
		        .build();
		
		VerifiablePresentation verifiablePresentation = VerifiablePresentation.builder()
		        .verifiableCredential(verifiableCredential)
		        .holder(URI.create("did:key:z6MkwBZ6oiJ71ovCohPfdsgBrQinMXnFn6wJxVZHpZEpSh8x"))
		        .build();

		byte[] testEd25519PrivateKey2 = Hex.decodeHex("984b589e121040156838303f107e13150be4a80fc5088ccba0b0bdc9b1d89090de8777a28f8da1a74e7a13090ed974d879bf692d001cddee16e4cc9f84b60580".toCharArray());

		Ed25519Signature2018LdSigner signer2 = new Ed25519Signature2018LdSigner(testEd25519PrivateKey2);
		signer2.setCreated(new Date());
		signer2.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_AUTHENTICATION);
		signer2.setVerificationMethod(URI.create("did:key:z6MkwBZ6oiJ71ovCohPfdsgBrQinMXnFn6wJxVZHpZEpSh8x#z6MkwBZ6oiJ71ovCohPfdsgBrQinMXnFn6wJxVZHpZEpSh8x"));
		signer2.setDomain("example.com");
		signer2.setNonce("343s$FSFDa-");
		try {
			LdProof ldProof2 = signer2.sign(verifiablePresentation);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonLDException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return verifiablePresentation.toJson(true);
	}
}
