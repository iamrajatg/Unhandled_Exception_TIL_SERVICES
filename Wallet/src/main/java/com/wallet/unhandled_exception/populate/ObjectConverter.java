package com.wallet.unhandled_exception.populate;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.DecoderException;
import com.wallet.unhandled_exception.encryption.Base58;
import com.wallet.unhandled_exception.model.DID_Doc;
import com.wallet.unhandled_exception.model.KeyAgreement;
import com.wallet.unhandled_exception.model.PublicKey;
import com.wallet.unhandled_exception.service.Codec;

public class ObjectConverter {
	
	public static PublicKey populatePublicKey(String publicKey, String didURL) throws DecoderException
	{
		PublicKey pk = new PublicKey();
		
		pk.setId(didURL);
		pk.setType("Ed25519VerificationKey2018");
		pk.setController(didURL.split("\\#")[0]);
		pk.setPublicKeyBase58(Base58.encode(Codec.decode(publicKey)));
		
		return pk;
	}
	
	public static KeyAgreement populateKeyAgreement(String publicKey, String didURL) throws DecoderException
	{
		KeyAgreement ka = new KeyAgreement();
		
		ka.setId(didURL);
		ka.setType("Ed25519VerificationKey2018");
		ka.setController(didURL.split("\\#")[0]);
		ka.setPublicKeyBase58(Base58.encode(Codec.decode(publicKey)));
		
		return ka;
	}
	
	public static DID_Doc populatedoc(String publicKey, String didURL) throws DecoderException
	{
		DID_Doc doc = new DID_Doc();
		List<String> cont = new ArrayList<>();
		List<String> authen = new ArrayList<>();
		List<String> asser = new ArrayList<>();
		List<String> capadel = new ArrayList<>();
		List<String> capainvo = new ArrayList<>();
		List<PublicKey> pk = new ArrayList<>();
		List<KeyAgreement> ka = new ArrayList<>();
		
		cont.add("https://w3.org/ns/did/v1");		
		pk.add(populatePublicKey(publicKey, didURL));
		authen.add(didURL);
		asser.add(didURL);
		capadel.add(didURL);
		capainvo.add(didURL);
		ka.add(populateKeyAgreement(publicKey, didURL));
		
		doc.setContext(cont);
		doc.setId(didURL.split("\\#")[0]);
		doc.setPublickey(pk);		
		doc.setAuthentication(authen);
		doc.setAssertionMethod(asser);
		doc.setCapabilityDelegation(capadel);
		doc.setCapabilityInvocation(capainvo);
		doc.setKeyAgreement(ka);
		
		return doc;
	}
}
