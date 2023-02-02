package com.wallet.unhandled_exception.response;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.google.crypto.tink.subtle.Hex;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.wallet.unhandled_exception.exceptions.Inaccurate;
import com.wallet.unhandled_exception.exceptions.NullExceptions;
import com.wallet.unhandled_exception.model.DID_Doc;
import com.wallet.unhandled_exception.populate.ObjectConverter;
import com.wallet.unhandled_exception.service.Codec;
import com.wallet.unhandled_exception.service.Conversion;
import com.wallet.unhandled_exception.service.CreateDIDWeb;
import com.wallet.unhandled_exception.service.FileEdit;

import foundation.identity.jsonld.JsonLDException;

public class Response {	
	static final String domain = "https://ipuresults.co.in/til";
	private static final Logger logger = LoggerFactory.getLogger(Response.class);  
	
	public static JsonObject convertToJsonObject(String request)
	{
		Gson gson = new Gson();
		JsonElement element = gson.fromJson(request, JsonElement.class);
		JsonObject jsonObj = element.getAsJsonObject();
		
		return jsonObj;
	}
	
	public static FinalResponse keyResponse(String publicKey,String privateKey) throws DecoderException 
	{
		String didKey = "did:key:" + Codec.multibase_encode(publicKey);
		
		
		String didURL = didKey + "#" + "keys-1";
		
		DID_Doc did_Doc = new DID_Doc();
		did_Doc = ObjectConverter.populatedoc(publicKey, didURL);			
		
		FinalResponse response = new FinalResponse();
		response.setDid_key(didKey);
		response.setDid_document(did_Doc);
		response.setPublicKey(publicKey);
		response.setPrivateKey(privateKey);
		
		return response;
	}
	
	public static FinalResponse webResponse(String publicKey,String privateKey) throws  IOException, DecoderException
	{
		String rand_identifier = RandomStringUtils.randomAlphanumeric(16);			
		String didWeb = CreateDIDWeb.create(domain) + ":dids:" + rand_identifier;
		String didWebURL = didWeb + "#" + "keys-1";
		
		DID_Doc did_Doc = new DID_Doc();
		did_Doc = ObjectConverter.populatedoc(publicKey, didWebURL);			
		FileEdit.uploadFTPD(rand_identifier, did_Doc);
		
		FinalResponse response = new FinalResponse();
		response.setDid_web(didWeb);
		response.setDid_document(did_Doc);
		response.setPublicKey(publicKey);
		response.setPrivateKey(privateKey);
		return response;
	}
	
	public static FinalResponse genResponse(String request) throws  NullExceptions, IOException, Inaccurate, DecoderException, JsonLDException
	{		
		String publicKey,privateKey, method;		
		JsonObject jsonObj = convertToJsonObject(request);
		try {
			Date t1 = Calendar.getInstance().getTime();
			
//			publicKey = jsonObj.get("publicKey").toString();		
//			publicKey = Conversion.toString(publicKey);		
			byte[] publicKeyBytes = new byte[32];
			byte[] privateKeyBytes = new byte[64];
			Ed25519Provider.get().generateEC25519KeyPair(publicKeyBytes,privateKeyBytes);
			publicKey = Hex.encode(publicKeyBytes);
			privateKey = Hex.encode(privateKeyBytes);
			
			method = jsonObj.get("method").toString();			
			method =  Conversion.toString(method);			
		
			if(StringUtils.isEmpty(method)) 				
				throw new NullExceptions();		
			else if(!(method.equalsIgnoreCase("web") || method.equalsIgnoreCase("key")))
				throw new Inaccurate();
			
			if(method.equalsIgnoreCase("key"))
			{
				logger.info("TIME TAKEN by method to create DOC KEY in ms: {}",
						Calendar.getInstance().getTime().getTime() - t1.getTime());			
				return keyResponse(publicKey,privateKey);
			}
			
			else if(method.equalsIgnoreCase("web"))
			{
				logger.info("TIME TAKEN by method to create DOC WEB in ms: {}",
						Calendar.getInstance().getTime().getTime() - t1.getTime());			
				return webResponse(publicKey,privateKey);
			}		
			
					
		}
		catch(NullPointerException e)
		{
			logger.error("Error  as value entered is null with message", e.getMessage(),
					e);
		}
		catch(IllegalArgumentException e) {
			logger.error("Error as key entered is unreadable with message", e.getMessage(),
					e);
		}
		catch(Exception e){
			logger.error("Error with message", e.getMessage(),
					e);
		}
				
		return null;
	}
}
