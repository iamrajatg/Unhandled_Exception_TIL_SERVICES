package com.wallet.unhandled_exception.controller;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.SigningError;
import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.jsonld.VerifiableCredentialContexts;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2018LdSigner;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier;

@CrossOrigin
@RestController
@RequestMapping("/wallet")
public class APIs {
	VerifiableCredential verifiableCredential;
	@GetMapping("/sign")
	public String signin() throws DecoderException, IOException, GeneralSecurityException, JsonLDException, SigningError, DocumentError
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

		verifiableCredential = VerifiableCredential.builder()
		        .context(VerifiableCredentialContexts.JSONLD_CONTEXT_W3C_2018_CREDENTIALS_EXAMPLES_V1)
		        .type("TOIPlusSubscription")
		        .id(URI.create("http://toi.com/credentials/3732"))
		        .issuer(URI.create("did:toi:76e12ec712ebc6f1c221ebfeb1f"))
		        .issuanceDate(JsonLDUtils.stringToDate("2023-01-13T18:56:59Z"))
		        .expirationDate(JsonLDUtils.stringToDate("2023-03-04T18:56:59Z"))
		        .credentialSubject(credentialSubject)
		        .build();

		byte[] testEd25519PrivateKey;	
		testEd25519PrivateKey = Hex.decodeHex("984b589e121040156838303f107e13150be4a80fc5088ccba0b0bdc9b1d89090de8777a28f8da1a74e7a13090ed974d879bf692d001cddee16e4cc9f84b60580".toCharArray());
		
		Ed25519Signature2018LdSigner signer = new Ed25519Signature2018LdSigner(testEd25519PrivateKey);
		signer.setCreated(new Date());
		signer.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD);
		signer.setVerificationMethod(URI.create("did:toi:76e12ec712ebc6f1c221ebfeb1f#keys-1"));
		try {
			LdProof ldProof = signer.sign(verifiableCredential);
		} catch (IOException | GeneralSecurityException | JsonLDException e) {
			e.printStackTrace();
		}
		
//		
//		KeyPair kp = new KeyPair();
//		kp.setPrivateKey(testEd25519PrivateKey);
//		
//		
//		VerificationMethod vm =new VerificationMethod();
//		vm.setId(URI.create("http://toi.com/credentials/3732"));
//		vm.setType("Prime Sub");
//		vm.setController(URI.create("did:toi:76e12ec712ebc6f1c221ebfeb1f#keys-1"));
//		ProofOptions po;
//		ProofOptions.create("Prime Sub", vm, URI.create("http://toi.com/credentials/3732")) ;
//		
//		
//		return Vc.sign(URI.create("http://example.com/credentials/3732"), kp, 
//							ProofOptions.create("Prime Sub", vm, URI.create("http://example.com/credentials/3732")))
//								.getExpanded();
		
		
//		 Vc.verify(verifiableCredential)
//		    .isValid();
		return verifiableCredential.toJson(true);
		
//		byte[] testEd25519PublicKey = Hex.decodeHex("de8777a28f8da1a74e7a13090ed974d879bf692d001cddee16e4cc9f84b60580".toCharArray());
//
////		VerifiableCredential verifiableCredential1 = VerifiableCredential.fromJson(new FileReader("input.jsonld"));
//		VerifiableCredential verifiableCredential1 = VerifiableCredential.fromJson(verifiableCredential.toJson());
//		Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(testEd25519PublicKey);
//		return verifier.verify(verifiableCredential1);
	}
	
	@GetMapping("/verify")
	public boolean verify() throws DecoderException, IOException, GeneralSecurityException, JsonLDException
	{
		byte[] testEd25519PublicKey = Hex.decodeHex("de8777a28f8da1a74e7a13090ed974d879bf692d001cddee16e4cc9f84b60580".toCharArray());
		String cred = "{\r\n"
				+ "  \"@context\" : [ \"https://www.w3.org/2018/credentials/v1\", \"https://www.w3.org/2018/credentials/examples/v1\" ],\r\n"
				+ "  \"type\" : [ \"VerifiableCredential\", \"TOIPlusSubscription\" ],\r\n"
				+ "  \"id\" : \"http://toi.com/credentials/3732\",\r\n"
				+ "  \"issuer\" : \"did:toi:76e12ec712ebc6f1c221ebfeb1f\",\r\n"
				+ "  \"issuanceDate\" : \"2023-01-13T18:56:59Z\",\r\n"
				+ "  \"expirationDate\" : \"2023-03-04T18:56:59Z\",\r\n"
				+ "  \"credentialSubject\" : {\r\n"
				+ "    \"id\" : \"did:toi:ebfeb1f712ebc6f1c276e12ec21\",\r\n"
				+ "    \"company\" : \"Times_of_India\",\r\n"
				+ "    \"Exclusive\" : {\r\n"
				+ "      \"name\" : \"Rupal_Goyal\",\r\n"
				+ "      \"type\" : \"Prime_Subscriber\"\r\n"
				+ "    }\r\n"
				+ "  },\r\n"
				+ "  \"proof\" : {\r\n"
				+ "    \"type\" : \"Ed25519Signature2018\",\r\n"
				+ "    \"created\" : \"2022-12-27T07:29:51Z\",\r\n"
				+ "    \"proofPurpose\" : \"assertionMethod\",\r\n"
				+ "    \"verificationMethod\" : \"did:toi:76e12ec712ebc6f1c221ebfeb1f#keys-1\",\r\n"
				+ "    \"jws\" : \"eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..Ec47AcurXDrXhx9m7UAMXWWs6OqAgBlP1sydvRMkytRCuMiAfasskm3cYDS6_bga5PDCSYddq1ueHwCeOmGqBA\"\r\n"
				+ "  }\r\n"
				+ "}";
		VerifiableCredential verifiableCredential = VerifiableCredential.fromJson(cred);
		Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(testEd25519PublicKey);
		return verifier.verify(verifiableCredential);
		


 
    

}
	
}
