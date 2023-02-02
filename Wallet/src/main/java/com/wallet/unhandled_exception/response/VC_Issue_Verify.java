package com.wallet.unhandled_exception.response;

import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.VerifiablePresentation;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.shaded.json.parser.JSONParser;
import com.vc.unhandled_exception.encryption.Base58;
import com.vc.unhandled_exception.model.VerifyResponse;
import com.vc.unhandled_exception.service.Issue_Verify;
import com.wallet.unhandled_exception.controller.Verifiable_Presentations;
import com.wallet.unhandled_exception.exceptions.NullExceptions;
import com.wallet.unhandled_exception.service.Codec;
import com.wallet.unhandled_exception.service.Conversion;
import com.wallet.unhandled_exception.service.CreateDIDWeb;
import com.wallet.unhandled_exception.utility.FTPD;

import foundation.identity.jsonld.JsonLDException;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2018LdSigner;

public class VC_Issue_Verify {
	
	private static final Logger logger = LoggerFactory.getLogger(VC_Issue_Verify.class);
	
	static final String PRIVATE_KEY = "4cf8394de5f8fc66301aac3bfe13c1778cd922323827499096ad5e717297fc8267f270bad09157546f658ef2eeda8c9e5f0fffaf9a0a616a3f73b3c7683ecee7";
	static final String PUBLIC_KEY = "67f270bad09157546f658ef2eeda8c9e5f0fffaf9a0a616a3f73b3c7683ecee7";
	
	public static JsonObject convertToJsonObject(String request)
	{
		Gson gson = new Gson();
		JsonElement element = gson.fromJson(request, JsonElement.class);
		JsonObject jsonObj = element.getAsJsonObject();
		
		return jsonObj;
	}
	
	public static String readJsonforWeb(String location)
	{
		JSONParser parser = new JSONParser();
	      try {
	    	 String publicKeyJson, publicKeyBase58;
	         Object obj = parser.parse(new FileReader(location));
	         JSONObject jsonObject = (JSONObject)obj;
	         publicKeyJson = jsonObject.get("publickey").toString();
	         JsonObject jsonObj = convertToJsonObject(publicKeyJson);
	         publicKeyBase58 = jsonObj.get("publicKeyBase58").toString();			
	         publicKeyBase58 =  Conversion.toString(publicKeyBase58);
	         
	         return publicKeyBase58;             
	      } 
	      catch(Exception e) {
	    	  logger.error("Public Key could not be found for DID WEB", e.getMessage(),
						e);
	      }
	      return null;
	}
	
	public static String getPublicKeyfromWeb(String uri)
	{
		FTPD.download(uri);		
		return readJsonforWeb("D:/Downloads/did.json");
	}
	
	public static byte[] getPublicKeyfromDoc(FinalResponse res)
	{
		byte[] publickey = new byte[32];
		String didpublickeyBase58 = res.getDid_key();			
		if(StringUtils.isEmpty(didpublickeyBase58))			
		{
			didpublickeyBase58 = res.getDid_web();	
			String uri = CreateDIDWeb.read(didpublickeyBase58);
			didpublickeyBase58 = getPublicKeyfromWeb(uri);
			publickey = Base58.decode(didpublickeyBase58);
		}
		else
		{
			didpublickeyBase58 = didpublickeyBase58.replaceAll("did:key:", "");				
			
			try {
				publickey = Codec.multibase_decode(didpublickeyBase58);
			} 
			catch (DecoderException e) {
				logger.error("Could not decode the public key from DID KEY", e.getMessage(),
						e);
			}
		}
		
		return publickey;
	}
	
	@SuppressWarnings("unchecked")
	public static String issueVC(String request)
	{		
		JsonObject jsonObj = convertToJsonObject(request);
		try {
			String subjectDID, issuerDID, duration, type, claimsJsonString;
			byte[] didpublickey = new byte[32];
			//didpublickey = getPublicKeyfromDoc(res);
			Integer dura;			
			
			claimsJsonString = jsonObj.get("claims").toString();				
			Map<String, Object> claims = new HashMap<String, Object>();
			ObjectMapper mapper = new ObjectMapper();
			claims =  mapper.readValue(claimsJsonString, Map.class);						
			
			subjectDID = jsonObj.get("subjectDID").toString();			
			subjectDID =  Conversion.toString(subjectDID);		
			
			issuerDID = jsonObj.get("issuerDID").toString();			
			issuerDID =  Conversion.toString(issuerDID);
			
			duration = jsonObj.get("duration").toString();			
			duration =  Conversion.toString(duration);
			dura = Integer.parseInt(duration);			
			
			type = jsonObj.get("type").toString();			
			type =  Conversion.toString(type);
					
			if(StringUtils.isEmpty(claimsJsonString) || StringUtils.isEmpty(subjectDID) 
					|| StringUtils.isEmpty(issuerDID) || StringUtils.isEmpty(duration) || StringUtils.isEmpty(type)) 				
				throw new NullExceptions();
			
			Date t1 =  Calendar.getInstance().getTime();
			String vc = Issue_Verify.issueVC(claims, PRIVATE_KEY, subjectDID, issuerDID, dura, type);
			
			logger.info("TIME TAKEN by sdk to issue VC in ms: {}",
					Calendar.getInstance().getTime().getTime() - t1.getTime());
			
			return vc;
		}
		catch(NullPointerException e)
		{			
			logger.error("Error as value entered is null with message", e.getMessage(),
							e);
		}
		catch(Exception e){
			logger.error("Error with message", e.getMessage(),
					e);
		}
				
		return null;
	}
	
	public static com.vc.unhandled_exception.model.VerifyResponse verifyVC(String request)
	{
		JsonObject jsonObj = convertToJsonObject(request);		
		
		try {
			String credential;
			byte[] didpublickey = new byte[32];;				
			//didpublickey = getPublicKeyfromDoc(res);
			
			credential = jsonObj.get("credential").toString();			
			//credential =  Conversion.toString(credential);
			
			if(StringUtils.isEmpty(credential)) 				
				throw new NullExceptions();	
			
			Date t1 = Calendar.getInstance().getTime();
			com.vc.unhandled_exception.model.VerifyResponse verify = null;
			verify = Issue_Verify.verifyVC(credential);	
			
			logger.info("TIME TAKEN by sdk to verify VC in ms: {}",
					Calendar.getInstance().getTime().getTime() - t1.getTime());
			
			return verify;
		}
		catch(NullPointerException e)
		{
			logger.error("Error  as value entered is null with message", e.getMessage(),
							e);
		}
		catch(Exception e){
			logger.error("Error with message", e.getMessage(),
					e);
		}
				
		return null;
	}
	
	public static com.vc.unhandled_exception.model.VerifyResponse verifyVP(String request)
	{
		JsonObject jsonObj = convertToJsonObject(request);		
		
		try {
			String presentation;
			String credential;
			String holder;
			byte[] didpublickey = new byte[32];;				
			//didpublickey = getPublicKeyfromDoc(res);
			
		
			
			JsonElement presentationObj = jsonObj.get("presentation");
			presentation = presentationObj.toString();
			JsonElement credentialObj = ((JsonObject)presentationObj).get("verifiableCredential");
			credential = credentialObj.toString();
			holder = ((JsonObject) presentationObj).get("holder").getAsString();
			//credential =  Conversion.toString(credential);
			
			if(StringUtils.isEmpty(presentation)) 				
				throw new NullExceptions();	
			
			Date t1 = Calendar.getInstance().getTime();
			com.vc.unhandled_exception.model.VerifyResponse verifyVC = null;
			
			verifyVC = Issue_Verify.verifyVC(credential);
			com.vc.unhandled_exception.model.VerifyResponse verifyVP = Verifiable_Presentations.verifyVP(presentation,holder);
			
			com.vc.unhandled_exception.model.VerifyResponse verify = new VerifyResponse();
			System.out.println("vc error"+verifyVC.getError());
			System.out.println("vp error"+verifyVP.getError());
			System.out.println(verifyVC.getVerified());
			System.out.println(verifyVP.getVerified());
			if(verifyVC.getVerified().equals("true") && verifyVP.getVerified().equals("true")) {
				verify.setVerified("true");
			}
			else {
				String vcError =  verifyVC.getError();
				String vpError =  verifyVP.getError();
				verify.setVerified("false");
				if(vpError!=null && vpError.length()>0) {
					verify.setError(vpError);
				}
				else if(vcError!=null && vcError.length()>0) {
					verify.setError(vcError);
				}
				
			}
			
			logger.info("TIME TAKEN by sdk to verify VC & VP in ms: {}",
					Calendar.getInstance().getTime().getTime() - t1.getTime());
			
			return verify;
		}
		catch(NullPointerException e)
		{
			logger.error("Error  as value entered is null with message", e.getMessage(),
							e);
		}
		catch(Exception e){
			logger.error("Error with message", e.getMessage(),
					e);
		}
				
		return null;
	}
	
	public static String createVP(String request)
	{
		JsonObject jsonObj = convertToJsonObject(request);		
		
		try {
			String credential;
			String holderPrivateKey;
			String holderDid;
			
			credential = jsonObj.get("credential").toString();	
			holderPrivateKey = jsonObj.get("privateKey").getAsString();
			holderDid = jsonObj.get("holderDid").getAsString();
			
			if(StringUtils.isEmpty(credential) || StringUtils.isEmpty(holderPrivateKey) || StringUtils.isEmpty(holderDid)) 				
				throw new NullExceptions();	
			
			byte[] holderPrivateKeyBytes = Hex.decodeHex(holderPrivateKey.toCharArray());
			
			VerifiableCredential verifiableCredential = VerifiableCredential.fromJson(credential);
			
			VerifiablePresentation verifiablePresentation = VerifiablePresentation.builder()
			        .verifiableCredential(verifiableCredential)
			        .holder(URI.create(holderDid))
			        .build();
			
			Ed25519Signature2018LdSigner signer = new Ed25519Signature2018LdSigner(holderPrivateKeyBytes);
			signer.setCreated(new Date());
			signer.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_AUTHENTICATION);
			signer.setVerificationMethod(URI.create(holderDid));
			signer.setDomain("ipuresults.co.in");
			signer.setNonce("343s$FSFDa-");
			
			LdProof ldProof = signer.sign(verifiablePresentation);
			
			return verifiablePresentation.toJson(true);
		}
		catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonLDException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch(NullPointerException e)
		{
			logger.error("Error  as value entered is null with message", e.getMessage(),
							e);
		}
		catch(Exception e){
			logger.error("Error with message", e.getMessage(),
					e);
		}
				
		return null;
	}

}
